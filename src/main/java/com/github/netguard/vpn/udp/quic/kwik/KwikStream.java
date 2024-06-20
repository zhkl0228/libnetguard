package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import com.github.netguard.vpn.udp.quic.Http3StreamForward;
import com.github.netguard.vpn.udp.quic.QuicStreamForward;
import net.luminis.quic.QuicStream;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;

class KwikStream implements QuicStreamForward.QuicStream {

    static void forward(net.luminis.quic.QuicStream clientStream, net.luminis.quic.QuicStream serverStream, boolean bidirectional, ExecutorService executorService, Http2SessionKey sessionKey, Http2Filter http2Filter) {
        QuicStreamForward.QuicStream server = new KwikStream(serverStream);
        QuicStreamForward.QuicStream client = new KwikStream(clientStream);
        if (http2Filter != null && http2Filter.filterHost(sessionKey.getSession().getHostName(), true)) {
            Http3StreamForward s2c = new Http3StreamForward(true, bidirectional, server, client, sessionKey, http2Filter);
            if (bidirectional) {
                Http3StreamForward c2s = new Http3StreamForward(false, true, client, server, sessionKey, http2Filter);
                s2c.setPeer(c2s);
                executorService.submit(c2s);
            }
            executorService.submit(s2c);
        } else {
            executorService.submit(new QuicStreamForward(true, bidirectional, server, client));
            if (bidirectional) {
                executorService.submit(new QuicStreamForward(false, true, client, server));
            }
        }
    }

    private final QuicStream stream;

    private KwikStream(QuicStream stream) {
        this.stream = stream;
    }

    @Override
    public int getStreamId() {
        return stream.getStreamId();
    }

    @Override
    public void resetStream(int applicationProtocolErrorCode) {
        stream.resetStream(applicationProtocolErrorCode);
    }

    @Override
    public InputStream openInputStream() {
        return stream.getInputStream();
    }

    @Override
    public OutputStream openOutputStream() {
        return stream.getOutputStream();
    }
}

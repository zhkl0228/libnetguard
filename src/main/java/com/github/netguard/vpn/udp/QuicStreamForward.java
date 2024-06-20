package com.github.netguard.vpn.udp;

import com.github.netguard.Inspector;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import net.luminis.quic.QuicStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;

class QuicStreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(QuicStreamForward.class);

    static void forward(QuicStream clientStream, QuicStream serverStream, boolean bidirectional, ExecutorService executorService, Http2SessionKey sessionKey, Http2Filter http2Filter) {
        if (http2Filter != null && http2Filter.filterHost(sessionKey.getSession().getHostName(), true)) {
            Http3StreamForward s2c = new Http3StreamForward(true, bidirectional, serverStream, clientStream, sessionKey, http2Filter);
            if (bidirectional) {
                Http3StreamForward c2s = new Http3StreamForward(false, true, clientStream, serverStream, sessionKey, http2Filter);
                s2c.setPeer(c2s);
                executorService.submit(c2s);
            }
            executorService.submit(s2c);
        } else {
            executorService.submit(new QuicStreamForward(true, bidirectional, serverStream, clientStream));
            if (bidirectional) {
                executorService.submit(new QuicStreamForward(false, true, clientStream, serverStream));
            }
        }
    }

    final boolean server;
    final boolean bidirectional;
    final QuicStream from, to;

    QuicStreamForward(boolean server, boolean bidirectional, QuicStream from, QuicStream to) {
        this.server = server;
        this.bidirectional = bidirectional;
        this.from = from;
        this.to = to;
    }

    void doForward(byte[] buf, int read, DataOutputStream outputStream) throws IOException {
        outputStream.write(buf, 0, read);
    }

    @Override
    public void run() {
        try (InputStream inputStream = from.getInputStream();
             OutputStream outputStream = to.getOutputStream();
             DataOutputStream dataOutput = new DataOutputStream(outputStream)) {
            byte[] buf = new byte[2048];
            while (true) {
                try {
                    int read = inputStream.read(buf);
                    log.debug("{} read {} bytes bidirectional={} from {} to {}", server ? "Server" : "Client", read, bidirectional, from, to);
                    if (read == -1) {
                        throw new EOFException();
                    }
                    if (read > 0) {
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(Arrays.copyOf(buf, read), (server ? "Server" : "Client") + " forward from=" + from + ", to=" + to));
                        }
                        doForward(buf, read, dataOutput);
                        outputStream.flush();
                    }
                } catch (IOException e) {
                    onEOF(dataOutput);
                    log.trace("forward from={}, to={}", from, to, e);
                    break;
                }
            }
        } catch (IOException e) {
            log.debug("forward stream from={}, to={}", from, to, e);
        } catch (Exception e) {
            log.warn("forward stream from={}, to={}", from, to, e);
        }
        log.debug("{} exiting {}", server ? "Server" : "Client", getClass().getSimpleName());
    }

    void onEOF(DataOutputStream outputStream) throws IOException {
    }

}

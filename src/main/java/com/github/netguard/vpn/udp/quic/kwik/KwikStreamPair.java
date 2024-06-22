package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.quic.QuicStreamPair;
import net.luminis.quic.QuicStream;

import java.io.InputStream;
import java.io.OutputStream;

class KwikStreamPair implements QuicStreamPair {

    private final QuicStream stream;

    KwikStreamPair(QuicStream stream) {
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

    @Override
    public String toString() {
        return String.valueOf(stream);
    }
}

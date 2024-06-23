package com.github.netguard.vpn.udp.quic.netty;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslEngine;
import io.netty.incubator.codec.quic.QuicSslSessionContext;

import java.util.List;

public class QuicSslContextWrapper extends QuicSslContext {

    private final QuicSslContext wrapper;
    private final String peerHost;
    private final int peerPort;

    public QuicSslContextWrapper(QuicSslContext wrapper, String peerHost, int peerPort) {
        this.wrapper = wrapper;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    @Override
    public QuicSslEngine newEngine(ByteBufAllocator alloc) {
        return newEngine(alloc, peerHost, peerPort);
    }

    @Override
    public QuicSslEngine newEngine(ByteBufAllocator alloc, String peerHost, int peerPort) {
        return wrapper.newEngine(alloc, peerHost, peerPort);
    }

    @Override
    public QuicSslSessionContext sessionContext() {
        return wrapper.sessionContext();
    }

    @Override
    public boolean isClient() {
        return wrapper.isClient();
    }

    @Override
    public List<String> cipherSuites() {
        return wrapper.cipherSuites();
    }

    @SuppressWarnings("deprecation")
    @Override
    public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
        return wrapper.applicationProtocolNegotiator();
    }

}

package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.quic.QuicServer;
import net.luminis.quic.server.ServerConnector;
import net.luminis.tls.engine.TlsServerEngineFactory;

import java.io.IOException;
import java.net.InetSocketAddress;

class KwikServer implements QuicServer {

    private final ServerConnector serverConnector;
    private final InetSocketAddress forwardAddress;
    private final TlsServerEngineFactory tlsServerEngineFactory;

    KwikServer(ServerConnector serverConnector, InetSocketAddress forwardAddress, TlsServerEngineFactory tlsServerEngineFactory) {
        this.serverConnector = serverConnector;
        this.forwardAddress = forwardAddress;
        this.tlsServerEngineFactory = tlsServerEngineFactory;
    }

    @Override
    public InetSocketAddress getForwardAddress() {
        return forwardAddress;
    }

    @Override
    public void close() throws IOException {
        serverConnector.shutdown();
        tlsServerEngineFactory.close();
    }

}

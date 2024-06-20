package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.quic.QuicServer;
import net.luminis.quic.server.ServerConnector;

import java.io.IOException;
import java.net.InetSocketAddress;

public class KwikServer implements QuicServer {

    private final ServerConnector serverConnector;
    private final InetSocketAddress forwardAddress;

    KwikServer(ServerConnector serverConnector, InetSocketAddress forwardAddress) {
        this.serverConnector = serverConnector;
        this.forwardAddress = forwardAddress;
    }

    @Override
    public InetSocketAddress getForwardAddress() {
        return forwardAddress;
    }

    @Override
    public void close() throws IOException {
        serverConnector.shutdown();
    }

}

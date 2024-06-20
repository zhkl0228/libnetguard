package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import net.luminis.quic.QuicClientConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

class KwikClientConnection implements ClientConnection {

    private static final Logger log = LoggerFactory.getLogger(KwikClientConnection.class);

    private final QuicClientConnection connection;

    KwikClientConnection(QuicClientConnection connection) {
        this.connection = connection;
    }

    @Override
    public KwikHandshakeResult handshake(Http2Session session) throws IOException {
        connection.connect();
        List<X509Certificate> chain = connection.getServerCertificateChain();
        X509Certificate peerCertificate = chain.get(0);
        String handshakeApplicationProtocol = connection.getHandshakeApplicationProtocol();
        return new KwikHandshakeResult(peerCertificate, handshakeApplicationProtocol, session, connection);
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

}

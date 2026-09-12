package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import tech.kwik.core.QuicClientConnection;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

class KwikClientConnection implements ClientConnection {

    private final QuicClientConnection connection;

    /**
     * KwikProvider 提供给服务端的那一个 ALPN。kwik 只提供了这一个，也没有暴露协商结果的接口，
     * 而 RFC 7301 要求服务端只能从客户端提供的列表里选，所以握手成功就意味着服务端选的是它。
     */
    private final String applicationProtocol;

    KwikClientConnection(QuicClientConnection connection, String applicationProtocol) {
        this.connection = connection;
        this.applicationProtocol = applicationProtocol;
    }

    @Override
    public KwikHandshakeResult handshake(Http2Session session) throws IOException {
        connection.connect();
        List<X509Certificate> chain = connection.getServerCertificateChain();
        X509Certificate peerCertificate = chain.get(0);
        return new KwikHandshakeResult(peerCertificate, applicationProtocol, session, connection);
    }

    @Override
    public void close() {
        connection.close();
    }

}

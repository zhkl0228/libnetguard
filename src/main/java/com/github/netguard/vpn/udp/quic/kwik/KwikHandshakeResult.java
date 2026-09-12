package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.udp.quic.HandshakeResult;
import com.github.netguard.vpn.udp.quic.QuicServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;

class KwikHandshakeResult implements HandshakeResult {

    private static final Logger log = LoggerFactory.getLogger(KwikHandshakeResult.class);

    private final X509Certificate peerCertificate;
    private final String handshakeApplicationProtocol;
    private final Http2Session session;
    private final QuicClientConnection connection;

    KwikHandshakeResult(X509Certificate peerCertificate, String handshakeApplicationProtocol,
                        Http2Session session, QuicClientConnection connection) {
        this.peerCertificate = peerCertificate;
        this.handshakeApplicationProtocol = handshakeApplicationProtocol;
        this.session = session;
        this.connection = connection;
    }

    @Override
    public QuicServer startServer(InspectorVpn vpn, Http2Filter http2Filter) throws Exception {
        if (handshakeApplicationProtocol == null || handshakeApplicationProtocol.isBlank()) {
            throw new IllegalStateException("handshakeApplicationProtocol=" + handshakeApplicationProtocol);
        }
        ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedBidirectionalStreams(KwikProxy.MAX_CONCURRENT_PEER_INITIATED_STREAMS)
                .maxOpenPeerInitiatedUnidirectionalStreams(KwikProxy.MAX_CONCURRENT_PEER_INITIATED_STREAMS)
                .build();
        ServerConnector.Builder builder = ServerConnector.builder();
        ServerCertificate.ServerContext serverContext = serverCertificate.getServerContext(vpn.getRootCert());
        serverContext.configServerConnector(builder);
        tech.kwik.core.log.Logger serverLogger;
        if (log.isDebugEnabled()) {
            serverLogger = new PrintStreamLogger(System.out);
            serverLogger.logDebug(true);
            serverLogger.logWarning(true); // BaseLogger 里默认 false，不开就连 kwik 的协议告警都收不到
        } else {
            serverLogger = new NullLogger();
        }
        DatagramSocket socket = new DatagramSocket(0);
        ServerConnector serverConnector = builder
                .withPort(1) // placeholder
                .withSocket(socket)
                .withConfiguration(serverConnectionConfig)
                .withLogger(serverLogger)
                .build();
        // 先注册再 start：ALPN 表是解析 ClientHello 时查的（ApplicationProtocolRegistry
        // #selectSupportedApplicationProtocol），空表会让 kwik 抛 NoApplicationProtocolAlert，
        // 在握手阶段就关掉连接——连 createConnection 都不会调，症状是完全收不到流。
        serverConnector.registerApplicationProtocol(handshakeApplicationProtocol, new KwikProxy(vpn.getExecutorService(), connection, session, http2Filter));
        serverConnector.start();
        int listenPort = socket.getLocalPort();
        log.debug("handshakeApplicationProtocol={}, listenPort={}, filterHttp3={}", handshakeApplicationProtocol, listenPort, http2Filter);
        InetSocketAddress forwardAddress = new InetSocketAddress("127.0.0.1", listenPort);
        return new KwikServer(serverConnector, forwardAddress);
    }

    @Override
    public String toString() {
        return "KwikHandshakeResult{" +
                "peerCertificate=" + peerCertificate +
                ", handshakeApplicationProtocol='" + handshakeApplicationProtocol + '\'' +
                '}';
    }

}

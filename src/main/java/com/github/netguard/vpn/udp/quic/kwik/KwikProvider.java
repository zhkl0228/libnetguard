package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.log.NullLogger;

import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;

public class KwikProvider extends QuicProxyProvider {

    private static final Logger log = LoggerFactory.getLogger(KwikProvider.class);

    @Override
    public ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout) throws SocketException, UnknownHostException {
        String applicationProtocol = selectApplicationProtocol(packetRequest);
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        builder.applicationProtocol(applicationProtocol);
        tech.kwik.core.log.Logger clientLogger;
        if (log.isDebugEnabled()) {
            clientLogger = new PrintStreamLogger(System.err);
            clientLogger.logDebug(true);
            clientLogger.logWarning(true); // BaseLogger 里默认 false，不开就连 kwik 的协议告警都收不到
        } else {
            clientLogger = new NullLogger();
        }
        QuicClientConnection connection = builder
                .uri(URI.create(String.format("https://%s:%d", packetRequest.hostName, packetRequest.port)))
                .proxy(packetRequest.serverIp)
                .logger(clientLogger)
                .connectTimeout(connectTimeout)
                .build();
        log.debug("newClientConnection: applicationProtocol={}, packetRequest={}", applicationProtocol, packetRequest);
        return new KwikClientConnection(connection, applicationProtocol);
    }

    /**
     * kwik 的 Builder 只能提供一个 ALPN，所以按客户端自己的优先级从它提供的列表里挑一个。
     * 挑中的值既发给真实服务端，也由 {@link KwikHandshakeResult#startServer} 注册成 MITM 服务端
     * 回给客户端的 ALPN，所以必须出自客户端的列表——回一个它没提供过的，客户端会以
     * no_application_protocol 拒绝握手。
     */
    private static String selectApplicationProtocol(PacketRequest packetRequest) {
        for (String applicationProtocol : packetRequest.applicationLayerProtocols) {
            if (PacketRequest.HTTP3_APPLICATION_LAYER_PROTOCOLS.contains(applicationProtocol)) {
                return applicationProtocol;
            }
        }
        throw new IllegalStateException("newClientConnection applicationLayerProtocols=" + packetRequest.applicationLayerProtocols);
    }

}

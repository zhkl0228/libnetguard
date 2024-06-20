package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.log.NullLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;

public class KwikProvider extends QuicProxyProvider {

    private static final Logger log = LoggerFactory.getLogger(KwikProvider.class);

    @Override
    public ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout) throws SocketException, UnknownHostException {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        for (String applicationLayerProtocol : packetRequest.applicationLayerProtocols) {
            builder.applicationProtocol(applicationLayerProtocol);
        }
        net.luminis.quic.log.Logger clientLogger;
        if (log.isDebugEnabled()) {
            clientLogger = new PrintStreamLogger(System.err);
            clientLogger.logDebug(true);
        } else {
            clientLogger = new NullLogger();
        }
        QuicClientConnection connection = builder
                .uri(URI.create(String.format("https://%s:%d", packetRequest.hostName, packetRequest.port)))
                .proxy(packetRequest.serverIp)
                .logger(clientLogger)
                .connectTimeout(connectTimeout)
                .build();
        return new KwikClientConnection(connection);
    }

}

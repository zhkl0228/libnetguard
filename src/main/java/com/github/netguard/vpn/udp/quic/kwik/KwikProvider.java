package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.UDPRelay;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
import net.luminis.quic.DatagramSocketFactory;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.log.NullLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;

public class KwikProvider extends QuicProxyProvider {

    private static final Logger log = LoggerFactory.getLogger(KwikProvider.class);

    private static class UdpProxySocketFactory implements DatagramSocketFactory {
        private final InetSocketAddress udpProxy;
        private final Duration connectTimeout;
        private final InetSocketAddress serverAddress;
        public UdpProxySocketFactory(InetSocketAddress udpProxy, Duration connectTimeout, InetSocketAddress serverAddress) {
            this.udpProxy = udpProxy;
            this.connectTimeout = connectTimeout;
            this.serverAddress = serverAddress;
        }
        @Override
        public DatagramSocket createSocket(InetAddress destination) throws SocketException {
            try {
                return UDPRelay.createRelayProxySocket(udpProxy, serverAddress, connectTimeout.toSeconds());
            } catch (SocketException e) {
                throw e;
            } catch (IOException e) {
                throw new SocketException(e.getMessage());
            }
        }
    }

    @Override
    public ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout, InetSocketAddress udpProxy) throws SocketException, UnknownHostException {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        for (String applicationLayerProtocol : packetRequest.applicationLayerProtocols) {
            builder.applicationProtocol(applicationLayerProtocol);
        }
        if(udpProxy != null) {
            builder.socketFactory(new UdpProxySocketFactory(udpProxy, connectTimeout, new InetSocketAddress(packetRequest.serverIp, packetRequest.port)));
        }
        net.luminis.quic.log.Logger clientLogger;
        if (log.isDebugEnabled()) {
            clientLogger = new PrintStreamLogger(System.err);
            clientLogger.logDebug(true);
        } else {
            clientLogger = new NullLogger();
        }
        QuicClientConnection connection = builder
                .uri(URI.create(String.format("https://%s:%d", packetRequest.hostName, udpProxy == null ? packetRequest.port : udpProxy.getPort())))
                .proxy(udpProxy == null ? packetRequest.serverIp : udpProxy.getHostString())
                .logger(clientLogger)
                .connectTimeout(connectTimeout)
                .build();
        log.debug("newClientConnection: serverAddress={}, udpProxy={}", connection.getServerAddress(), udpProxy);
        return new KwikClientConnection(connection);
    }

}

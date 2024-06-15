package com.github.netguard.vpn.udp;

import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.extension.ServerNameExtension;
import net.luminis.tls.handshake.ClientHello;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Message;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class PacketRequest {

    private static final Logger log = LoggerFactory.getLogger(PacketRequest.class);

    public final String serverIp;
    public final int port;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    public final Message dnsQuery;

    public byte[] getPrologue() {
        return Arrays.copyOf(buffer, length);
    }

    private final byte[] buffer;
    private final int length;

    public PacketRequest(byte[] buffer, int length, ClientHello clientHello, Message dnsQuery, InetSocketAddress serverAddress) {
        this.serverIp = serverAddress.getAddress().getHostAddress();
        this.port = serverAddress.getPort();
        this.dnsQuery = dnsQuery;
        this.buffer = buffer;
        this.length = length;

        if (clientHello != null) {
            String hostName = null;
            List<String> applicationLayerProtocols = null;
            for (Extension extension : clientHello.getExtensions()) {
                if (extension instanceof ServerNameExtension) {
                    ServerNameExtension serverNameExtension = (ServerNameExtension) extension;
                    hostName = serverNameExtension.getHostName();
                } else if (extension instanceof ApplicationLayerProtocolNegotiationExtension) {
                    ApplicationLayerProtocolNegotiationExtension applicationLayerProtocolNegotiationExtension = (ApplicationLayerProtocolNegotiationExtension) extension;
                    applicationLayerProtocols = applicationLayerProtocolNegotiationExtension.getProtocols();
                }
            }
            if(hostName == null || applicationLayerProtocols == null || applicationLayerProtocols.isEmpty()) {
                log.warn("hostname={}, applicationLayerProtocols={}, clientHello={}", hostName, applicationLayerProtocols, clientHello);
            }
            this.hostName = hostName;
            this.applicationLayerProtocols = applicationLayerProtocols == null ? Collections.emptyList() : new ArrayList<>(applicationLayerProtocols);
        } else {
            this.hostName = null;
            this.applicationLayerProtocols = Collections.emptyList();
        }
    }

    @Override
    public String toString() {
        return "PacketRequest{" +
                "serverIp='" + serverIp + '\'' +
                ", port=" + port +
                ", hostName='" + hostName + '\'' +
                ", applicationLayerProtocols=" + applicationLayerProtocols +
                ", dnsQuery=" + dnsQuery +
                '}';
    }
}

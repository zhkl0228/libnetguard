package com.github.netguard.vpn.udp;

import com.github.netguard.vpn.AcceptUdpResult;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.ConnectRequest;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tls.JA3Signature;
import com.github.netguard.vpn.tls.QuicClientHello;
import com.github.netguard.vpn.tls.TlsSignature;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Message;
import tech.kwik.agent15.extension.ApplicationLayerProtocolNegotiationExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.ServerNameExtension;
import tech.kwik.agent15.handshake.ClientHello;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class PacketRequest implements ConnectRequest<AcceptUdpResult> {

    private static final Logger log = LoggerFactory.getLogger(PacketRequest.class);

    public final String serverIp;
    public final int port;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    public final Message dnsQuery;
    private final TlsSignature tlsSignature;

    @Override
    public byte[] getPrologue() {
        return Arrays.copyOf(buffer, length);
    }

    @Override
    public TlsSignature getTlsSignature() {
        return tlsSignature;
    }

    @Override
    public ClientOS getClientOS() {
        return vpn.getClientOS();
    }

    @Override
    public String getExtraData() {
        return vpn.getExtraData();
    }

    @Override
    public Application[] queryApplications() {
        return vpn.queryApplications(packet.hashCode());
    }

    private final byte[] buffer;
    private final int length;
    private final InspectorVpn vpn;
    private final Packet packet;

    @Override
    public AcceptUdpResult disconnect() {
        System.err.printf("discardUdp: packetRequest=%s%n", this);
        return AcceptUdpResult.rule(AcceptRule.Discard);
    }

    public PacketRequest(byte[] buffer, int length, ClientHello clientHello, Message dnsQuery, InetSocketAddress serverAddress, InspectorVpn vpn, Packet packet) {
        this.serverIp = serverAddress.getAddress().getHostAddress();
        this.port = serverAddress.getPort();
        this.dnsQuery = dnsQuery;
        this.buffer = buffer;
        this.length = length;
        this.vpn = vpn;
        this.packet = packet;

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
                    if (!applicationLayerProtocols.contains("h3")) {
                        throw new IllegalStateException("applicationLayerProtocols=" + applicationLayerProtocols);
                    }
                }
            }
            if(hostName == null || applicationLayerProtocols == null || applicationLayerProtocols.isEmpty()) {
                log.warn("hostname={}, applicationLayerProtocols={}, clientHello={}", hostName, applicationLayerProtocols, clientHello);
            }
            this.hostName = hostName;
            this.applicationLayerProtocols = applicationLayerProtocols == null ? Collections.emptyList() : new ArrayList<>(applicationLayerProtocols);
            this.tlsSignature = new JA3Signature(new QuicClientHello(clientHello, hostName, applicationLayerProtocols));
        } else {
            this.hostName = null;
            this.applicationLayerProtocols = Collections.emptyList();
            this.tlsSignature = null;
        }
    }

    @Override
    public String toString() {
        return String.format("PacketRequest{%s:%d => %s:%d, hostName='%s', isDNSQuery='%s', applicationLayerProtocols=%s}", packet.saddr, packet.sport, serverIp, port, hostName, dnsQuery != null, applicationLayerProtocols);
    }
}

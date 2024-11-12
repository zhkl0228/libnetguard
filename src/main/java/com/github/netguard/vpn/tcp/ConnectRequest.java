package com.github.netguard.vpn.tcp;

import com.github.netguard.vpn.AcceptTcpResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.tls.TlsSignature;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpRequest;

import java.util.List;

public class ConnectRequest implements com.github.netguard.vpn.ConnectRequest {

    public final String serverIp;
    public final int port;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    private final byte[] prologue;
    public final HttpRequest httpRequest;
    private final TlsSignature tlsSignature;

    @Override
    public byte[] getPrologue() {
        return prologue;
    }

    @Override
    public TlsSignature getTlsSignature() {
        return tlsSignature;
    }

    @Override
    public Application[] queryApplications() {
        return vpn.queryApplications(packet.hashCode());
    }

    private final InspectorVpn vpn;
    private final Packet packet;

    ConnectRequest(InspectorVpn vpn, Packet packet, String hostName, List<String> applicationLayerProtocols, byte[] prologue,
                   HttpRequest httpRequest, TlsSignature tlsSignature) {
        this.vpn = vpn;
        this.packet = packet;
        this.serverIp = packet.daddr;
        this.port = packet.dport;
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
        this.prologue = prologue;
        this.httpRequest = httpRequest;
        this.tlsSignature = tlsSignature;
    }

    @Override
    public ClientOS getClientOS() {
        return vpn.getClientOS();
    }

    public AcceptTcpResult.AcceptResultBuilder connectTcpDirect() {
        return AcceptTcpResult.builder(AllowRule.CONNECT_TCP);
    }

    @SuppressWarnings("unused")
    public AcceptTcpResult.AcceptResultBuilder tryMITM(boolean filterH2) {
        if (isSSL()) {
            boolean isH2 = applicationLayerProtocols.contains(Vpn.HTTP2_PROTOCOL);
            if (filterH2 && isH2) {
                return AcceptTcpResult.builder(AllowRule.FILTER_H2).setRedirectHost(hostName);
            } else {
                return AcceptTcpResult.builder(AllowRule.CONNECT_SSL).setRedirectHost(hostName);
            }
        } else {
            return connectTcpDirect();
        }
    }

    public AcceptTcpResult disconnect() {
        return AcceptTcpResult.builder(AllowRule.DISCONNECT).build();
    }

    public boolean isAppleHost() {
        return isSSL() && (hostName.endsWith(".icloud.com") ||
                hostName.endsWith(".apple.com") ||
                hostName.endsWith(".icloud.com.cn"));
    }

    public boolean isAndroidHost() {
        return isSSL() && (hostName.endsWith(".googleapis.com") ||
                hostName.endsWith(".google.com") ||
                "www.gstatic.com".equals(hostName));
    }

    public boolean isSSL() {
        return hostName != null;
    }

    /**
     * 是否为普通 http 请求
     */
    public boolean isHttp() {
        return httpRequest != null;
    }

    @Override
    public String toString() {
        return "ConnectRequest{" +
                "serverIp='" + serverIp + '\'' +
                ", port=" + port +
                ", hostName='" + hostName + '\'' +
                ", applicationLayerProtocols=" + applicationLayerProtocols +
                '}';
    }

}

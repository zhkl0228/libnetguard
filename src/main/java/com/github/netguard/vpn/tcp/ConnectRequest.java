package com.github.netguard.vpn.tcp;

import com.github.netguard.vpn.AcceptTcpResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.tls.TlsSignature;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;

import java.util.List;

public class ConnectRequest implements com.github.netguard.vpn.ConnectRequest<AcceptTcpResult> {

    public final String serverIp;
    public final int port;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    private final byte[] prologue;
    public final HttpRequest httpRequest;
    private final TlsSignature tlsSignature;
    private final boolean ssl;

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
                   HttpRequest httpRequest, TlsSignature tlsSignature, boolean ssl) {
        this.vpn = vpn;
        this.packet = packet;
        this.serverIp = packet.daddr;
        this.port = packet.dport;
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
        this.prologue = prologue;
        this.httpRequest = httpRequest;
        this.tlsSignature = tlsSignature;
        this.ssl = ssl;
    }

    @Override
    public ClientOS getClientOS() {
        return vpn.getClientOS();
    }

    @Override
    public String getExtraData() {
        return vpn.getExtraData();
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

    @Override
    public AcceptTcpResult disconnect() {
        System.err.printf("disconnectTcp serverIp=%s, port=%d, hostName=%s, applicationLayerProtocols=%s%n", this.serverIp, this.port, this.hostName, this.applicationLayerProtocols);
        return AcceptTcpResult.builder(AllowRule.DISCONNECT).build();
    }

    @Override
    public AcceptTcpResult readMorePrologue(int needPrologueCount) {
        int prologueLength = prologue.length;
        if (needPrologueCount <= 0 || needPrologueCount < prologueLength) {
            throw new IllegalStateException("needPrologueCount=" + needPrologueCount + ", prologueLength=" + prologueLength);
        }
        return AcceptTcpResult.builder(AllowRule.READ_MORE_PROLOGUE).setNeedPrologueCount(needPrologueCount).build();
    }

    public boolean isAppleHost() {
        if (httpRequest != null) {
            String userAgent = httpRequest.headers().get(HttpHeaderNames.USER_AGENT);
            if (userAgent != null && userAgent.startsWith("com.apple.")) {
                return true;
            }
        }
        String hostName = this.hostName;
        if(hostName == null && httpRequest != null) {
            hostName = httpRequest.headers().get(HttpHeaderNames.HOST.toString());
        }
        if (hostName == null) {
            return false;
        }
        return hostName.endsWith(".icloud.com") ||
                hostName.endsWith(".apple.com") ||
                hostName.endsWith(".icloud.com.cn") ||
                hostName.endsWith(".cdn-apple.com") ||
                hostName.endsWith(".icloud-content.com") ||
                "dispatcher.is.autonavi.com".equals(hostName) ||
                "api.smoot.apple.cn".equals(hostName);
    }

    public boolean isAndroidHost() {
        String hostName = this.hostName;
        if(hostName == null && httpRequest != null) {
            hostName = httpRequest.headers().get(HttpHeaderNames.HOST.toString());
        }
        if (hostName == null) {
            return false;
        }
        return hostName.endsWith(".googleapis.com") ||
                hostName.endsWith(".google.com") ||
                "www.gstatic.com".equals(hostName);
    }

    public boolean isSSL() {
        return ssl;
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

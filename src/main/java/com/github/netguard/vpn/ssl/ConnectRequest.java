package com.github.netguard.vpn.ssl;

import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;

import java.util.List;

public class ConnectRequest {

    public final String serverIp;
    public final int port;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    public final byte[] prologue;

    ConnectRequest(String serverIp, int port, String hostName, List<String> applicationLayerProtocols, byte[] prologue) {
        this.serverIp = serverIp;
        this.port = port;
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
        this.prologue = prologue;
    }

    public AcceptResult.AcceptResultBuilder connectTcpDirect() {
        return AcceptResult.builder(AllowRule.CONNECT_TCP);
    }

    public AcceptResult disconnect() {
        return AcceptResult.builder(AllowRule.DISCONNECT).build();
    }

    public boolean isAppleHost() {
        return isSSL() && (hostName.endsWith(".icloud.com") ||
                hostName.endsWith(".apple.com"));
    }

    public boolean isAndroidHost() {
        return isSSL() && (hostName.endsWith(".googleapis.com") ||
                hostName.endsWith(".google.com") ||
                "www.gstatic.com".equals(hostName));
    }

    public boolean isSSL() {
        return hostName != null;
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

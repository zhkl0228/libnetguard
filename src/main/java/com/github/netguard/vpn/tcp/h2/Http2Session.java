package com.github.netguard.vpn.tcp.h2;

import java.util.Objects;

public class Http2Session {

    private final String clientIp, serverIp;
    private final int clientPort, serverPort;
    private final String hostName;

    public Http2Session(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
        this.clientIp = clientIp;
        this.serverIp = serverIp;
        this.clientPort = clientPort;
        this.serverPort = serverPort;
        this.hostName = hostName;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getServerIp() {
        return serverIp;
    }

    public int getClientPort() {
        return clientPort;
    }

    public int getServerPort() {
        return serverPort;
    }

    public String getHostName() {
        return hostName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Http2Session h2Session = (Http2Session) o;
        return clientPort == h2Session.clientPort && serverPort == h2Session.serverPort && Objects.equals(clientIp, h2Session.clientIp) && Objects.equals(serverIp, h2Session.serverIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientIp, serverIp, clientPort, serverPort);
    }

    @Override
    public String toString() {
        return clientIp + ":" + clientPort + " => " + serverIp + ":" + serverPort;
    }
}

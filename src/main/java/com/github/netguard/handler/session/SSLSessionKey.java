package com.github.netguard.handler.session;

import org.krakenapps.pcap.decoder.tcp.TcpSessionKeyImpl;

import java.net.InetAddress;

public class SSLSessionKey extends TcpSessionKeyImpl {

    private final String hostName;

    public SSLSessionKey(InetAddress clientIp, InetAddress serverIp, int clientPort, int serverPort, String hostName) {
        super(clientIp, serverIp, clientPort, serverPort);
        this.hostName = hostName;
    }

    public String getHostName() {
        return hostName;
    }

}

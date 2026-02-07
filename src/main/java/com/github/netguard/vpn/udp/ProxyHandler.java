package com.github.netguard.vpn.udp;

import java.net.InetSocketAddress;

public interface ProxyHandler {

    default void initContext(ProxyContext context) {
    }

    /**
     * 客户端发出
     */
    int handleUdpClient(InetSocketAddress clientAddress, byte[] packet, int length);

    /**
     * 服务端收到
     */
    int handleUdpServer(InetSocketAddress serverAddress, byte[] packet, int length);

}

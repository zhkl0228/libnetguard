package com.github.netguard.vpn.udp;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;

public interface ProxyContext {

    InetSocketAddress getClientAddress();
    InetSocketAddress getServerAddress();

    DatagramSocket getLocalSocket();
    DatagramSocket getRemoteSocket();

}

package com.github.netguard.vpn;

import java.net.InetSocketAddress;

public interface Vpn {

    InetSocketAddress getRemoteSocketAddress();

    void setPacketCapture(IPacketCapture packetCapture);

    boolean isTransparentProxying();

    void setDirectAllowAll();

    ClientOS getClientOS();

}

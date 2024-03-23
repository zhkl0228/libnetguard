package com.github.netguard.vpn;

import java.net.InetSocketAddress;

public interface Vpn {

    InetSocketAddress getRemoteSocketAddress();

    void setPacketCapture(IPacketCapture packetCapture);

    @SuppressWarnings("unused")
    boolean isTransparentProxying();

    void setDirectAllowAll();

    ClientOS getClientOS();

}

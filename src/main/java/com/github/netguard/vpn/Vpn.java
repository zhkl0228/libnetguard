package com.github.netguard.vpn;

import java.net.InetSocketAddress;

public interface Vpn {

    String HTTP2_PROTOCOL = "h2";

    InetSocketAddress getRemoteSocketAddress();

    void setPacketCapture(IPacketCapture packetCapture);

    @SuppressWarnings("unused")
    boolean isTransparentProxying();

    void setDirectAllowAll();

    ClientOS getClientOS();

}

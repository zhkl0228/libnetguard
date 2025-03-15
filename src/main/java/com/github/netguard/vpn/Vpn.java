package com.github.netguard.vpn;

import eu.faircode.netguard.ConnectionListener;

import java.net.InetSocketAddress;

public interface Vpn {

    String HTTP2_PROTOCOL = "h2";

    InetSocketAddress getRemoteSocketAddress();

    void setPacketCapture(IPacketCapture packetCapture);

    @SuppressWarnings("unused")
    boolean isTransparentProxying();

    void setDirectAllowAll();

    ClientOS getClientOS();

    void setConnectionListener(ConnectionListener connectionListener);

}

package com.github.netguard.vpn;

import java.net.InetSocketAddress;

public interface Vpn {

    InetSocketAddress getRemoteSocketAddress();

    void setPacketCapture(IPacketCapture packetCapture);

}

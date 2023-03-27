package com.github.netguard.vpn;

public interface Vpn {

    void setPacketCapture(IPacketCapture packetCapture);

    void enableMitm(int... sslPorts);

}

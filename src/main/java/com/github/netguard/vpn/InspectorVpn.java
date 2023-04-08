package com.github.netguard.vpn;

public interface InspectorVpn extends Vpn {

    int CONST_RAW_IP = 101;

    IPacketCapture getPacketCapture();

}

package com.github.netguard.vpn;

public interface InspectorVpn extends Vpn {

    IPacketCapture getPacketCapture();

    String[] queryApplications(int hash);

}

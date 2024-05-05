package com.github.netguard.vpn;

import eu.faircode.netguard.Application;

public interface InspectorVpn extends Vpn {

    IPacketCapture getPacketCapture();

    Application[] queryApplications(int hash);

}

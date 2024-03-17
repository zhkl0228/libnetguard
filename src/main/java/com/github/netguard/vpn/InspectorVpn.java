package com.github.netguard.vpn;

import eu.faircode.netguard.Package;

public interface InspectorVpn extends Vpn {

    IPacketCapture getPacketCapture();

    Package[] queryApplications(int hash);

}

package com.github.netguard.vpn;

import com.github.netguard.vpn.tcp.RootCert;
import eu.faircode.netguard.Application;

public interface InspectorVpn extends Vpn {

    IPacketCapture getPacketCapture();

    Application[] queryApplications(int hash);

    RootCert getRootCert();

}

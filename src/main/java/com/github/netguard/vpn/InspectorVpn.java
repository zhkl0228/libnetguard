package com.github.netguard.vpn;

import com.github.netguard.vpn.tcp.RootCert;
import eu.faircode.netguard.Application;

import java.util.concurrent.ExecutorService;

public interface InspectorVpn extends Vpn {

    IPacketCapture getPacketCapture();

    Application[] queryApplications(int hash);

    RootCert getRootCert();
    ExecutorService getExecutorService();

}

package com.legendsec.vpnclient;

import com.github.netguard.VpnServer;
import com.github.netguard.VpnServerBuilder;
import com.github.netguard.vpn.IPacketCapture;

import java.util.Collections;

public class SSLVpnMain {

    public static void main(String[] args) throws Exception {
        SSLVpnServer easyConnect = new SSLVpnServer("192.168.31.205", 443, 20250, Collections.emptyList());
        SSLVpnServer aTrust = new SSLVpnServer("192.168.31.206", 443, 20260, Collections.emptyList());
        VpnServerBuilder builder = VpnServerBuilder.create()
                .withPort(20240)
                .enableBroadcast(30)
                .enableTransparentProxying()
                .withVpnListener(vpn -> {
                    IPacketCapture packetCapture = new VPNPacketDecoder();
                    vpn.setPacketCapture(packetCapture);
                });
        VpnServer vpnServer = builder.startServer();
        System.out.println("Start vpn server on port: " + vpnServer.getPort());
        vpnServer.waitShutdown();
        easyConnect.close();
        aTrust.close();
    }

}
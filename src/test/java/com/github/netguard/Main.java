package com.github.netguard;

import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.ssl.SSLProxyV2;
import eu.faircode.netguard.ServiceSinkhole;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.INFO);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.INFO);
        Logger.getLogger(PacketDecoder.class).setLevel(Level.TRACE);
        VpnServer vpnServer = new VpnServer(0);
        vpnServer.enableBroadcast(10);
        vpnServer.setVpnListener(new VpnListener() {
            @Override
            public void onConnectClient(Vpn vpn) {
                IPacketCapture packetCapture = new PacketDecoder();
                vpn.setPacketCapture(packetCapture);
                vpn.enableMitm();
            }
        });
        vpnServer.start();

        System.out.println("vpn server listen on: " + vpnServer.getPort());
        Scanner scanner = new Scanner(System.in);
        String cmd;
        while ((cmd = scanner.nextLine()) != null) {
            if ("q".equals(cmd) || "exit".equals(cmd)) {
                break;
            }
        }
        vpnServer.shutdown();
    }

}
package com.github.netguard;

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
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.DEBUG);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.DEBUG);
        VpnServer vpnServer = new VpnServer();
        vpnServer.enableBroadcast(10);
        vpnServer.setVpnListener(new VpnListener() {
            @Override
            public void onConnectClient(Vpn vpn) {
                IPacketCapture packetCapture = new DebugPacketCapture();
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

    private static class DebugPacketCapture implements IPacketCapture {
        @Override
        public void onPacket(byte[] packetData, String type) {
        }
        @Override
        public void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
            System.out.printf("onSSLProxyEstablish %s:%d => %s:%d, hostName=%s%n", clientIp, clientPort, serverIp, serverPort, hostName);
        }
        @Override
        public void onSSLProxyTX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        }
        @Override
        public void onSSLProxyRX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        }
        @Override
        public void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
            System.out.printf("onSSLProxyFinish %s:%d => %s:%d, hostName=%s%n", clientIp, clientPort, serverIp, serverPort, hostName);
        }
    }

}
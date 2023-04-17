package com.github.netguard;

import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.ssl.SSLProxyV2;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.ServiceSinkhole;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.http.HttpDecoder;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.INFO);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.INFO);
        Logger.getLogger(PacketDecoder.class).setLevel(Level.INFO);
        Logger.getLogger(HttpDecoder.class).setLevel(Level.INFO);
        Logger.getLogger(HttpFrameForward.class).setLevel(Level.DEBUG);
        VpnServer vpnServer = new VpnServer();
        vpnServer.enableBroadcast(10);
        vpnServer.setVpnListener(new MyVpnListener());
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

    private static class MyVpnListener implements VpnListener, Http2Filter {
        @Override
        public void onConnectClient(Vpn vpn) {
            IPacketCapture packetCapture = new PacketDecoder() {
                @Override
                public Http2Filter getH2Filter() {
                    return MyVpnListener.this;
                }
            };
            vpn.setPacketCapture(packetCapture);
            vpn.enableMitm();
        }
        @Override
        public boolean acceptHost(String hostName) {
            if (hostName.endsWith("weixin.qq.com")) {
                return true;
            } else {
                System.out.println("NOT filter http2 host=" + hostName);
                return false;
            }
        }
    }

}
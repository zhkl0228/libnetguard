package com.github.netguard;

import cn.banny.auxiliary.Inspector;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import eu.faircode.netguard.ServiceSinkhole;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.DEBUG);
        final IPacketCapture packetCapture = new DebugPacketCapture("m.toutiao.com");
        VpnServer vpnServer = new VpnServer();
        vpnServer.setVpnListener(new VpnListener() {
            @Override
            public void onConnectClient(Vpn vpn) {
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
        private final Map<String, List<String>> dnsMap = new HashMap<>();

        public DebugPacketCapture(String... hosts) {
            try {
                for (String host : hosts) {
                    InetAddress[] addresses = InetAddress.getAllByName(host);
                    List<String> list = new ArrayList<>();
                    for (InetAddress address : addresses) {
                        if (address instanceof Inet4Address) {
                            list.add(address.getHostAddress());
                        }
                    }
                    dnsMap.put(host, Collections.unmodifiableList(list));
                }
                System.out.println(dnsMap);
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void onPacket(byte[] packetData, String type, int datalink) {
        }
        @Override
        public void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort) {
        }
        @Override
        public void onSSLProxyTX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
            Inspector.inspect(data, String.format("onSSLProxyTX %s:%d => %s:%d", clientIp, clientPort, serverIp, serverPort));
        }
        @Override
        public void onSSLProxyRX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
            Inspector.inspect(data, String.format("onSSLProxyRX %s:%d => %s:%d", clientIp, clientPort, serverIp, serverPort));
        }
        @Override
        public void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort) {
        }
        @Override
        public String resolveHost(String ip) {
            for (Map.Entry<String, List<String>> entry : dnsMap.entrySet()) {
                if (entry.getValue().contains(ip)) {
                    return entry.getKey();
                }
            }
            switch (ip) {
                case "111.123.48.8":
                case "125.94.50.240":
                case "124.227.186.252":
                case "219.128.78.184":
                case "219.128.78.186":
                case "219.128.78.147":
                    return "m.toutiao.com";
            }
            System.out.println("resolveHost: " + ip);
            return null;
        }
    }

}
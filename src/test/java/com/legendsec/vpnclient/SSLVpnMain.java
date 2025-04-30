package com.legendsec.vpnclient;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.VpnServer;
import com.github.netguard.VpnServerBuilder;
import com.github.netguard.vpn.IPacketCapture;

import java.util.Collections;

public class SSLVpnMain {

    public static void main(String[] args) throws Exception {
        SSLVpnServer server = new SSLVpnServer("wegu.zhongdinggroup.com", 443, 20250, Collections.emptyList());
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
        IoUtil.close(server);
    }

}
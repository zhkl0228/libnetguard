package com.github.netguard;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        VpnServer vpnServer = new VpnServer();
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
package com.legendsec.vpnclient;

import cn.hutool.core.codec.Base64;
import com.github.netguard.IPUtil;
import com.github.netguard.Inspector;
import junit.framework.TestCase;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class Base64Test extends TestCase {

    public void testBase64() {
        byte[] data = Base64.decode("eyJBY2Nlc3NNZXRob2QiOiAyMCwgIkFjY2Vzc1R5cGUiOiAyLCAiQXV0aElEIjogMSwgIkNlcnRQYXRoIjogIiIsICJDbGllbnREZXNjIjogIkFuZHJvaWQiLCAiQ2xpZW50SVAiOiAiIiwgIkNsaWVudEluZiI6ICIiLCAiRGV2aWNlSW5mbyI6IHsiYWRtaW5zIjogW10sICJhbnRpdmlydXMiOiAiMSIsICJkZXZpZCI6ICJjODk0NjcxMTQxY2FjNDVmNDQ2ZGM0MjFhYTNkMmZmZCIsICJpbWVpIjogIiIsICJtYW51ZmFjdHVyZXIiOiAiR29vZ2xlIiwgIm1vZGVsIjogIlBpeGVsIDQiLCAibmFtZSI6ICJQaXhlbCA0IiwgIm9zIjogIkFuZHJvaWQiLCAib3NfdmVyc2lvbiI6ICIxMyIsICJwYWNrYWdlX25hbWUiOiAiY29tLmxlZ2VuZHNlYy5zc2x2cG4iLCAicHJvZHVjdCI6ICJmbGFtZSIsICJyb290ZWQiOiAiMCIsICJzZXJpYWwiOiAidW5rbm93biIsICJ3aWZpX2FkZHJlc3MiOiAiMDAtMDAtMDAtMDAtMDAtMDAifSwgIkhvc3ROYW1lIjogIjE5Mi4xNjguMS4yMSIsICJOZWVkUXIiOiAwLCAiUGFzc3dvcmQiOiAiMUFkNHJEaDVjWG15IiwgIlJlbmV3IjogMCwgIlNlY01vYmkiOiAiMSIsICJTdWJBdXRoSUQiOiAxLCAiU3ViQXV0aFR5cGUiOiAwLCAiVGlja2V0IjogIjYyNDlERDAzNTE0MEFDMTlGODU5MkYyMzZCQjgwQ0RDOTIxNzAwMjI0NjFDQTJFRjAxMDAwMDAwMDAwMDAwMDAiLCAiVXNlck5hbWUiOiAiY2VzaGkiLCAiVXNlclR5cGUiOiAyLCAiYXBwX2lkZW50aWZ5IjogImNvbS5sZWdlbmRzZWMuc3NsdnBuIiwgImFwcF9vZW0iOiAic3RhbmRhcmQiLCAiYXBwX3BrZ25hbWUiOiAiY29tLmxlZ2VuZHNlYy5zc2x2cG4iLCAiYXBwX3ZlcnNpb24iOiAidjc5NSIsICJjbGllbnRfdmVyc2lvbiI6ICJza3kuMjAxNzA1MDEiLCAiZW1hcmsiOiAiIiwgImV4dHJhX1NlY01vYmkiOiAiMSIsICJleHRyYV9Vc2VyVHlwZSI6ICIyIiwgImV4dHJhX2NsaWVudF92ZXJzaW9uIjogInNreS4yMDE3MDUwMSIsICJleHRyYV9xcmNvZGVfZmxhZyI6ICIwIiwgImV4dHJhX3dpZmlfYWRkcmVzcyI6ICIwMC0wMC0wMC0wMC0wMC0wMCIsICJwb3J0IjogMjAyNTAsICJwcm90b192ZXJzaW9uIjogIjIiLCAidGlja2V0IjogIjYyNDlERDAzNTE0MEFDMTlGODU5MkYyMzZCQjgwQ0RDOTIxNzAwMjI0NjFDQTJFRjAxMDAwMDAwMDAwMDAwMDAifQ==");
        Inspector.inspect(data, "Base64");
    }

    public void testIP() {
        long addr = IPUtil.prefix2mask(8);
        InetAddress address = IPUtil.long2inet(addr);
        System.out.println(address);
    }

    public void testSSL() throws Exception {
        System.out.println(System.getProperty("jdk.tls.disabledAlgorithms"));
        try (SSLServerSocket serverSocket = (SSLServerSocket) SSLServerSocketFactory
                .getDefault().createServerSocket()) {

            System.out.println("##### Server supported protocols #####");
            for (String protocol : serverSocket.getSupportedProtocols()) {
                System.out.println(protocol);
            }

            System.out.println("##### Server enabled protocols #####");
            for (String protocol : serverSocket.getEnabledProtocols()) {
                System.out.println(protocol);
            }
        }

        System.out.println();

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory
                .getDefault().createSocket()) {

            System.out.println("##### Client supported protocols #####");
            for (String protocol : socket.getSupportedProtocols()) {
                System.out.println(protocol);
            }

            System.out.println("##### Client enabled protocols #####");
            for (String protocol : socket.getEnabledProtocols()) {
                System.out.println(protocol);
            }
        }
    }

}

package com.github.netguard.vpn;

import com.github.netguard.vpn.ssl.h2.Http2Filter;

public interface IPacketCapture {

    void onPacket(byte[] packetData, String type);
    void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName, String applicationProtocol);
    void onSSLProxyTX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyRX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName);

    void notifyFinish();

    boolean acceptTcp(String serverIp, int port);
    boolean acceptSSL(String hostName, String serverIp, int port);
    Http2Filter getH2Filter();

}

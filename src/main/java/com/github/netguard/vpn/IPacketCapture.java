package com.github.netguard.vpn;

public interface IPacketCapture {
    void onPacket(byte[] packetData, String type);
    void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName);
    void onSSLProxyTX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyRX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName);

    void notifyFinish();

}

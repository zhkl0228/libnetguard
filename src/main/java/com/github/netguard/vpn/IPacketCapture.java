package com.github.netguard.vpn;

public interface IPacketCapture {
    /**
     *
     */
    void onPacket(byte[] packetData, String type, int datalink);
    void onSSLProxyEstablish(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort);
    void onSSLProxyTX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyRX(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyFinish(java.lang.String clientIp, java.lang.String serverIp, int clientPort, int serverPort);

}

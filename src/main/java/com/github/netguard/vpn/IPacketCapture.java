package com.github.netguard.vpn;

import com.github.netguard.vpn.ssl.h2.Http2Filter;

import java.util.List;

public interface IPacketCapture {

    void onPacket(byte[] packetData, String type);
    void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName, String applicationProtocol);
    void onSSLProxyTx(String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyRx(String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName);

    void onSocketEstablish(String clientIp, String serverIp, int clientPort, int serverPort);
    void onSocketTx(String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSocketRx(String clientIp, java.lang.String serverIp, int clientPort, int serverPort, byte[] data);
    void onSocketFinish(String clientIp, String serverIp, int clientPort, int serverPort);

    void notifyFinish();

    /**
     * 默认返回 <code>null</code> 表示允许连接
     * @param hostName 如果是 SSL 不为 <code>null</code>
     */
    AcceptResult acceptSSL(String serverIp, int port, String hostName, List<String> applicationLayerProtocols);
    Http2Filter getH2Filter();

}

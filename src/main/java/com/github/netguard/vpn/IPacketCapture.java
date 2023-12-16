package com.github.netguard.vpn;

import com.github.netguard.vpn.ssl.h2.Http2Filter;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.List;

public interface IPacketCapture {

    void onPacket(byte[] packetData, String type);
    void onSSLProxyEstablish(InetSocketAddress client, InetSocketAddress server, String hostName, Collection<String> applicationProtocols, String selectedApplicationProtocol);
    void onSSLProxyTx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSSLProxyRx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSSLProxyFinish(InetSocketAddress client, InetSocketAddress server, String hostName);

    void onSocketEstablish(InetSocketAddress client, InetSocketAddress server);
    void onSocketTx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSocketRx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSocketFinish(InetSocketAddress client, InetSocketAddress server);

    void notifyFinish();

    /**
     * 默认返回 <code>null</code> 表示允许连接
     * @param hostName 如果是 SSL 不为 <code>null</code>
     */
    AcceptResult acceptSSL(String serverIp, int port, String hostName, List<String> applicationLayerProtocols, byte[] prologue);
    Http2Filter getH2Filter();

}

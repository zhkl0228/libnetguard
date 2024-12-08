package com.github.netguard.vpn;

import com.github.netguard.vpn.tcp.ConnectRequest;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.udp.DNSFilter;
import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;

import java.net.InetSocketAddress;
import java.util.Collection;

public interface IPacketCapture {

    void onPacket(byte[] packetData, String type);

    void onSSLProxyEstablish(InetSocketAddress client, InetSocketAddress server, String hostName,
                             Collection<String> applicationProtocols, String selectedApplicationProtocol, String application);
    void onSSLProxyTx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSSLProxyRx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSSLProxyFinish(InetSocketAddress client, InetSocketAddress server, String hostName);

    void onSocketEstablish(InetSocketAddress client, InetSocketAddress server);
    void onSocketTx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSocketRx(InetSocketAddress client, InetSocketAddress server, byte[] data);
    void onSocketFinish(InetSocketAddress client, InetSocketAddress server);

    void notifyVpnFinish();

    /**
     * 默认返回 <code>null</code> 表示允许连接
     */
    AcceptTcpResult acceptTcp(ConnectRequest connectRequest);
    AcceptUdpResult acceptUdp(PacketRequest packetRequest);

    Http2Filter getH2Filter();
    DNSFilter getDNSFilter();
    QuicProxyProvider getQuicProxyProvider();
    void replay();

}

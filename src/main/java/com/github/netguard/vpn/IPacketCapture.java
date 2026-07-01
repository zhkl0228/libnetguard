package com.github.netguard.vpn;

import com.github.netguard.handler.replay.Replay;
import com.github.netguard.vpn.tcp.ConnectRequest;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.ws.WebSocketFilter;
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

    /**
     * WebSocket 帧过滤/注入钩子(与 {@link Http2Filter} 对称)。默认 <code>null</code> 表示不启用。
     * 仅当连接被 MITM 解密(AllowRule.CONNECT_SSL/FILTER_H2)时生效。
     */
    default WebSocketFilter getWebSocketFilter() {
        return null;
    }

    DNSFilter getDNSFilter();
    QuicProxyProvider getQuicProxyProvider();
    void replay(Replay replay);

}

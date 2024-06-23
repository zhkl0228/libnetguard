package com.github.netguard.vpn.udp.quic;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.kwik.KwikProvider;
import com.github.netguard.vpn.udp.quic.netty.NettyProvider;

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Duration;

public abstract class QuicProxyProvider {

    public static QuicProxyProvider kwik() {
        return new KwikProvider();
    }

    public static QuicProxyProvider netty() {
        return new NettyProvider();
    }

    public abstract ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout, InetSocketAddress udpProxy) throws SocketException, UnknownHostException;

}

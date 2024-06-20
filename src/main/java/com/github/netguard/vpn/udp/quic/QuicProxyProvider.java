package com.github.netguard.vpn.udp.quic;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.kwik.KwikProvider;

import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Duration;

public abstract class QuicProxyProvider {

    public static QuicProxyProvider kwik() {
        return new KwikProvider();
    }

    public abstract ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout) throws SocketException, UnknownHostException;

}

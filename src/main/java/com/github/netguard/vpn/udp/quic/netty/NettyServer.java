package com.github.netguard.vpn.udp.quic.netty;

import com.github.netguard.vpn.udp.quic.QuicServer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;

import java.net.InetSocketAddress;

class NettyServer implements QuicServer {

    private final NioEventLoopGroup group;
    private final DatagramChannel datagramChannel;
    private final InetSocketAddress forwardAddress;

    NettyServer(NioEventLoopGroup group, DatagramChannel datagramChannel, InetSocketAddress forwardAddress) {
        this.group = group;
        this.datagramChannel = datagramChannel;
        this.forwardAddress = forwardAddress;
    }

    @Override
    public InetSocketAddress getForwardAddress() {
        return forwardAddress;
    }

    @Override
    public void close() {
        datagramChannel.close();
        group.shutdownGracefully();
    }

}

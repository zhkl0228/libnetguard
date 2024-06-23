package com.github.netguard.vpn.udp.quic.netty;

import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.incubator.codec.http3.Http3;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicChannelBootstrap;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class NettyProvider extends QuicProxyProvider {

    private static final Logger log = LoggerFactory.getLogger(NettyProvider.class);

    @Override
    public ClientConnection newClientConnection(PacketRequest packetRequest, Duration connectTimeout) {
        NioEventLoopGroup group = new NioEventLoopGroup(1);

        try {
            QuicSslContext context = QuicSslContextBuilder.forClient()
                    .applicationProtocols(packetRequest.applicationLayerProtocols.toArray(new String[0])).build();
            ChannelHandler codec = Http3.newQuicClientCodecBuilder()
                    .sslContext(new QuicSslContextWrapper(context, packetRequest.hostName, packetRequest.port))
                    .maxIdleTimeout(connectTimeout.toMillis(), TimeUnit.MILLISECONDS)
                    .initialMaxData(10000000)
                    .initialMaxStreamDataBidirectionalLocal(1000000)
                    .build();

            Bootstrap bs = new Bootstrap();
            Channel channel = bs.group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(codec)
                    .bind(0).sync().channel();

            InetSocketAddress remoteAddress = new InetSocketAddress(packetRequest.serverIp, packetRequest.port);
            QuicChannelBootstrap bootstrap = QuicChannel.newBootstrap(channel)
                    .remoteAddress(remoteAddress);
            log.debug("newClientConnection remoteAddress={}, bootstrap={}", remoteAddress, bootstrap);
            return new NettyClientConnection(group, channel, bootstrap);
        } catch (InterruptedException e) {
            throw new IllegalStateException("newClientConnection", e);
        }
    }

}

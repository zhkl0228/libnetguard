package com.github.netguard.vpn.udp.quic.netty;

import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.HandshakeResult;
import io.netty.channel.Channel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.incubator.codec.http3.Http3ClientConnectionHandler;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicChannelBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;

class NettyClientConnection implements ClientConnection {

    private static final Logger log = LoggerFactory.getLogger(NettyClientConnection.class);

    private final NioEventLoopGroup group;
    private final Channel channel;
    private final QuicChannelBootstrap bootstrap;

    NettyClientConnection(NioEventLoopGroup group, Channel channel, QuicChannelBootstrap bootstrap) {
        this.group = group;
        this.channel = channel;
        this.bootstrap = bootstrap;
    }

    private QuicChannel quicChannel;

    @Override
    public HandshakeResult handshake(Http2Session session) throws IOException {
        try {
            quicChannel = bootstrap
                    .handler(new Http3ClientConnectionHandler())
                    .connect()
                    .get();
            SSLEngine sslEngine = quicChannel.sslEngine();
            if (sslEngine == null) {
                throw new IllegalStateException("sslEngine is null");
            }
            String applicationProtocol = sslEngine.getApplicationProtocol();
            X509Certificate peerCertificate = (X509Certificate) sslEngine.getSession().getPeerCertificates()[0];
            log.debug("newClientConnection applicationProtocol={}, peerCertificate={}", applicationProtocol, peerCertificate);
            return new NettyHandshakeResult(peerCertificate, applicationProtocol, quicChannel);
        } catch (InterruptedException | ExecutionException e) {
            throw new IOException("handshake", e);
        }
    }

    @Override
    public void close() {
        if(quicChannel != null) {
            quicChannel.close();
        }
        channel.close();
        group.shutdownGracefully();
    }

}

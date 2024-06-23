package com.github.netguard.vpn.udp.quic.netty;

import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.udp.quic.HandshakeResult;
import com.github.netguard.vpn.udp.quic.QuicServer;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.EmptyHttpHeaders;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.incubator.codec.http3.Http3;
import io.netty.incubator.codec.http3.Http3FrameToHttpObjectCodec;
import io.netty.incubator.codec.http3.Http3ServerConnectionHandler;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

class NettyHandshakeResult implements HandshakeResult {

    private static final Logger log = LoggerFactory.getLogger(NettyHandshakeResult.class);

    private final X509Certificate peerCertificate;
    private final String handshakeApplicationProtocol;
    private final QuicChannel quicChannel;

    NettyHandshakeResult(X509Certificate peerCertificate, String applicationProtocol, QuicChannel quicChannel) {
        this.peerCertificate = peerCertificate;
        this.handshakeApplicationProtocol = applicationProtocol;
        this.quicChannel = quicChannel;
    }

    @Override
    public QuicServer startServer(InspectorVpn vpn, Http2Filter http2Filter) throws Exception {
        NioEventLoopGroup group = new NioEventLoopGroup(1);
        ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
        ServerCertificate.ServerContext serverContext = serverCertificate.getServerContext(vpn.getRootCert());
        KeyManagerFactory keyManagerFactory = serverContext.newKeyManagerFactory();
        QuicSslContext sslContext = QuicSslContextBuilder.forServer(keyManagerFactory, new String(serverContext.getKeyPassword()))
                .applicationProtocols(handshakeApplicationProtocol)
                .build();
        ChannelHandler codec = Http3.newQuicServerCodecBuilder()
                .sslContext(sslContext)
                .maxIdleTimeout(5, TimeUnit.SECONDS)
                .initialMaxData(10000000)
                .initialMaxStreamDataBidirectionalLocal(1000000)
                .initialMaxStreamDataBidirectionalRemote(1000000)
                .initialMaxStreamsBidirectional(100)
                .handler(new ChannelInitializer<QuicChannel>() {
                    @Override
                    protected void initChannel(QuicChannel ch) {
                        ch.pipeline().addLast(new Http3ServerConnectionHandler(new ServerRequestStreamInitializer()));
                    }
                }).build();
        Bootstrap bootstrap = new Bootstrap();
        Channel channel = bootstrap.group(group)
                .channel(NioDatagramChannel.class)
                .handler(codec)
                .bind(new InetSocketAddress(0)).sync().channel();
        DatagramChannel datagramChannel = (NioDatagramChannel) channel;
        log.debug("datagramChannel={}, port={}", datagramChannel, datagramChannel.localAddress().getPort());
        InetSocketAddress forwardAddress = new InetSocketAddress("127.0.0.1", datagramChannel.localAddress().getPort());
        return new NettyServer(group, datagramChannel, forwardAddress);
    }

    private class ServerRequestStreamInitializer extends ChannelInitializer<QuicStreamChannel> {
        @Override
        protected void initChannel(QuicStreamChannel serverStreamChannel) throws InterruptedException {
            log.debug("Server initChannel: {}", serverStreamChannel);
            ChannelPipeline pipeline = serverStreamChannel.pipeline();
            pipeline.addLast(new Http3FrameToHttpObjectCodec(true));

            QuicStreamChannel clientStreamChannel = Http3.newRequestStream(quicChannel, new NettyHandshakeResult.ClientRequestStreamInitializer(serverStreamChannel))
                    .sync()
                    .getNow();
            pipeline.addLast(new NettyHandshakeResult.HttpRequestServerHandler(clientStreamChannel));
        }
    }

    private static class HttpRequestServerHandler extends SimpleChannelInboundHandler<HttpObject> {
        private final QuicStreamChannel clientStreamChannel;

        public HttpRequestServerHandler(QuicStreamChannel clientStreamChannel) {
            this.clientStreamChannel = clientStreamChannel;
        }

        private HttpRequest request;
        private final ByteBuf content = Unpooled.buffer();

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
            if (msg instanceof HttpRequest) {
                request = (HttpRequest) msg;
            } else if (msg instanceof HttpContent) {
                HttpContent httpContent = (HttpContent) msg;
                content.writeBytes(httpContent.content());
            }
            log.debug("Server channelRead0: last={}, content={}, {}", msg == LastHttpContent.EMPTY_LAST_CONTENT, content, msg);
            if (msg == LastHttpContent.EMPTY_LAST_CONTENT) {
                HttpHeaders headers = request.headers();
                headers.remove(HttpHeaderNames.CONTENT_LENGTH);
                headers.setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
                clientStreamChannel
                        .writeAndFlush(new DefaultFullHttpRequest(request.protocolVersion(),
                                request.method(), request.uri(), content,
                                headers, EmptyHttpHeaders.INSTANCE))
                        .addListener(QuicStreamChannel.SHUTDOWN_OUTPUT);
            }
        }
    }

    private static class ClientRequestStreamInitializer extends ChannelInitializer<QuicStreamChannel> {
        private final QuicStreamChannel serverStreamChannel;

        public ClientRequestStreamInitializer(QuicStreamChannel serverStreamChannel) {
            this.serverStreamChannel = serverStreamChannel;
        }

        @Override
        protected void initChannel(QuicStreamChannel clientStreamChannel) {
            log.debug("Client initChannel: {}", clientStreamChannel);
            ChannelPipeline pipeline = clientStreamChannel.pipeline();
            pipeline.addLast(new Http3FrameToHttpObjectCodec(false));
            pipeline.addLast(new NettyHandshakeResult.HttpRequestClientHandler(serverStreamChannel));
        }
    }

    private static class HttpRequestClientHandler extends SimpleChannelInboundHandler<HttpObject> {
        private final QuicStreamChannel serverStreamChannel;

        public HttpRequestClientHandler(QuicStreamChannel serverStreamChannel) {
            this.serverStreamChannel = serverStreamChannel;
        }

        private HttpResponse response;
        private final ByteBuf content = Unpooled.buffer();

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
            if (msg instanceof HttpResponse) {
                response = (HttpResponse) msg;
            } else if (msg instanceof HttpContent) {
                HttpContent httpContent = (HttpContent) msg;
                content.writeBytes(httpContent.content());
            }
            log.debug("Client channelRead0: last={}, content={}, {}", msg == LastHttpContent.EMPTY_LAST_CONTENT, content, msg);
            if (msg == LastHttpContent.EMPTY_LAST_CONTENT) {
                serverStreamChannel.writeAndFlush(new DefaultFullHttpResponse(response.protocolVersion(),
                                response.status(), content,
                                response.headers(), EmptyHttpHeaders.INSTANCE))
                        .addListener(QuicStreamChannel.SHUTDOWN_OUTPUT);
            }
        }
    }
}

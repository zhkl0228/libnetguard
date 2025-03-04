package com.github.netguard.vpn.udp.quic.netty;

import cn.hutool.core.thread.ThreadUtil;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.h2.CancelResult;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import com.github.netguard.vpn.udp.quic.HandshakeResult;
import com.github.netguard.vpn.udp.quic.QuicServer;
import com.twitter.http2.NetGuardHttp2Headers;
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
import io.netty.handler.codec.http.HttpMethod;
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
import java.util.Map;
import java.util.concurrent.TimeUnit;

class NettyHandshakeResult implements HandshakeResult {

    private static final Logger log = LoggerFactory.getLogger(NettyHandshakeResult.class);

    private final X509Certificate peerCertificate;
    private final QuicChannel quicChannel;
    private final Http2Session session;

    NettyHandshakeResult(X509Certificate peerCertificate, QuicChannel quicChannel, Http2Session session) {
        this.peerCertificate = peerCertificate;
        this.quicChannel = quicChannel;
        this.session = session;
    }

    @Override
    public QuicServer startServer(InspectorVpn vpn, Http2Filter http2Filter) throws Exception {
        NioEventLoopGroup group = new NioEventLoopGroup(1,
                ThreadUtil.newNamedThreadFactory("netty-server-nio-event-loop", true));
        ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
        ServerCertificate.ServerContext serverContext = serverCertificate.getServerContext(vpn.getRootCert());
        KeyManagerFactory keyManagerFactory = serverContext.newKeyManagerFactory();
        QuicSslContext sslContext = QuicSslContextBuilder.forServer(keyManagerFactory, new String(serverContext.getKeyPassword()))
                .applicationProtocols(Http3.supportedApplicationProtocols())
                .build();
        ChannelHandler codec = Http3.newQuicServerCodecBuilder()
                .sslContext(sslContext)
                .maxIdleTimeout(1, TimeUnit.MINUTES)
                .initialMaxData(10000000)
                .initialMaxStreamDataBidirectionalLocal(1000000)
                .initialMaxStreamDataBidirectionalRemote(1000000)
                .initialMaxStreamsBidirectional(100)
                .handler(new ServerRequestStreamInitializer(http2Filter)).build();
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

    private class ServerRequestStreamHandler extends ChannelInitializer<QuicStreamChannel> {
        private final Http2Filter http2Filter;
        public ServerRequestStreamHandler(Http2Filter http2Filter) {
            this.http2Filter = http2Filter;
        }
        @Override
        protected void initChannel(QuicStreamChannel serverStreamChannel) throws InterruptedException {
            log.debug("Server initChannel: {}", serverStreamChannel);
            ChannelPipeline pipeline = serverStreamChannel.pipeline();
            pipeline.addLast(new Http3FrameToHttpObjectCodec(true));

            Http2SessionKey sessionKey = new Http2SessionKey(session, (int) serverStreamChannel.streamId(), true);
            boolean filter = http2Filter != null && http2Filter.filterHost(session.getHostName(), true);
            QuicStreamChannel clientStreamChannel = Http3.newRequestStream(quicChannel,
                            new NettyHandshakeResult.ClientRequestStreamInitializer(serverStreamChannel, sessionKey, filter ? http2Filter : null))
                    .sync()
                    .getNow();
            pipeline.addLast(new NettyHandshakeResult.HttpRequestServerHandler(clientStreamChannel, sessionKey, filter ? http2Filter : null));
        }
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            log.debug("exceptionCaught ctx={}", ctx, cause);
        }
    }

    private static class HttpRequestServerHandler extends SimpleChannelInboundHandler<HttpObject> {
        private final QuicStreamChannel clientStreamChannel;
        private final Http2SessionKey sessionKey;
        private final Http2Filter http2Filter;

        public HttpRequestServerHandler(QuicStreamChannel clientStreamChannel, Http2SessionKey sessionKey, Http2Filter http2Filter) {
            this.clientStreamChannel = clientStreamChannel;
            this.sessionKey = sessionKey;
            this.http2Filter = http2Filter;
        }

        private HttpRequest request;
        private final ByteBuf content = Unpooled.buffer();

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
            log.debug("Server channelRead0: last={}, content={}, msg={}", msg == LastHttpContent.EMPTY_LAST_CONTENT, content, msg);
            if (msg instanceof HttpRequest) {
                request = (HttpRequest) msg;
            } else if (msg instanceof HttpContent) {
                HttpContent httpContent = (HttpContent) msg;
                content.writeBytes(httpContent.content());
            } else {
                log.warn("Unexpected server message type: {}", msg);
            }
        }
        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            log.debug("channelReadComplete: request={}", request);
            byte[] requestData = new byte[content.readableBytes()];
            content.readBytes(requestData);
            if (http2Filter != null &&
                    http2Filter.filterHost(sessionKey.getSession().getHostName(), true)) {
                CancelResult result = http2Filter.cancelRequest(request, requestData, false);
                if (result != null) {
                    if (result.cancel) {
                        ctx.channel().close();
                    } else {
                        byte[] responseData = result.responseData;
                        HttpResponse response = result.response;
                        response.headers().set("X-Netguard-Fake-Response", sessionKey.toString());
                        http2Filter.filterRequest(sessionKey, request, new NetGuardHttp2Headers(), requestData);
                        HttpHeaders headers = response.headers();
                        headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
                        HttpResponse forward = new DefaultFullHttpResponse(response.protocolVersion(),
                                response.status(), Unpooled.wrappedBuffer(responseData),
                                headers, EmptyHttpHeaders.INSTANCE);
                        log.debug("Server forward response: {}", forward);
                        ctx.channel().writeAndFlush(forward);
                    }
                    clientStreamChannel.close();
                    return;
                }
            }
            HttpHeaders headers = new NetGuardHttp2Headers();
            for (Map.Entry<String, String> entry : request.headers().entries()) {
                headers.add(entry.getKey(), entry.getValue());
            }
            requestData = http2Filter == null ? requestData : http2Filter.filterRequest(sessionKey, request, headers, requestData);
            headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
            String methodHeader = headers.get(":method");
            HttpMethod method = methodHeader == null ? request.method() : HttpMethod.valueOf(methodHeader);
            headers.remove(":method");
            String pathHeader = headers.get(":path");
            String path = pathHeader == null ? request.uri() : pathHeader;
            headers.remove(":path");
            HttpRequest forward = new DefaultFullHttpRequest(request.protocolVersion(),
                    method,
                    path, Unpooled.wrappedBuffer(requestData),
                    headers, EmptyHttpHeaders.INSTANCE);
            log.debug("Server forward request: {}", forward);
            clientStreamChannel.writeAndFlush(forward);
        }
    }

    private static class ClientRequestStreamInitializer extends ChannelInitializer<QuicStreamChannel> {
        private final QuicStreamChannel serverStreamChannel;
        private final Http2SessionKey sessionKey;
        private final Http2Filter http2Filter;

        public ClientRequestStreamInitializer(QuicStreamChannel serverStreamChannel, Http2SessionKey sessionKey, Http2Filter http2Filter) {
            this.serverStreamChannel = serverStreamChannel;
            this.sessionKey = sessionKey;
            this.http2Filter = http2Filter;
        }

        @Override
        protected void initChannel(QuicStreamChannel clientStreamChannel) {
            log.debug("Client initChannel: {}", clientStreamChannel);
            ChannelPipeline pipeline = clientStreamChannel.pipeline();
            pipeline.addLast(new Http3FrameToHttpObjectCodec(false));
            pipeline.addLast(new HttpResponseClientHandler(serverStreamChannel, sessionKey, http2Filter));
        }
    }

    private static class HttpResponseClientHandler extends SimpleChannelInboundHandler<HttpObject> {
        private final QuicStreamChannel serverStreamChannel;
        private final Http2SessionKey sessionKey;
        private final Http2Filter http2Filter;

        public HttpResponseClientHandler(QuicStreamChannel serverStreamChannel, Http2SessionKey sessionKey, Http2Filter http2Filter) {
            this.serverStreamChannel = serverStreamChannel;
            this.sessionKey = sessionKey;
            this.http2Filter = http2Filter;
        }

        private HttpResponse response;
        private final ByteBuf content = Unpooled.buffer();

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
            log.debug("Client channelRead0: last={}, content={}, {}", msg == LastHttpContent.EMPTY_LAST_CONTENT, content, msg);
            if (msg instanceof HttpResponse) {
                response = (HttpResponse) msg;
            } else if (msg instanceof HttpContent) {
                HttpContent httpContent = (HttpContent) msg;
                content.writeBytes(httpContent.content());
            } else {
                log.warn("Unexpected client message type: {}", msg);
            }
        }
        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            byte[] responseData = new byte[content.readableBytes()];
            content.readBytes(responseData);
            HttpHeaders headers = new NetGuardHttp2Headers();
            HttpHeaders responseHeaders = response.headers();
            for(Map.Entry<String, String> entry : responseHeaders.entries()) {
                headers.add(entry.getKey(), entry.getValue());
            }
            responseData = http2Filter == null ? responseData : http2Filter.filterResponse(sessionKey, response, headers, responseData);
            headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
            HttpResponse forward = new DefaultFullHttpResponse(response.protocolVersion(),
                    response.status(), Unpooled.wrappedBuffer(responseData),
                    headers, EmptyHttpHeaders.INSTANCE);
            log.debug("Client forward response: {}", forward);
            serverStreamChannel.writeAndFlush(forward);
        }
    }

    private class ServerRequestStreamInitializer extends ChannelInitializer<QuicChannel> {
        private final Http2Filter http2Filter;
        public ServerRequestStreamInitializer(Http2Filter http2Filter) {
            this.http2Filter = http2Filter;
        }
        @Override
        protected void initChannel(QuicChannel ch) {
            ch.pipeline().addLast(new Http3ServerConnectionHandler(new ServerRequestStreamHandler(http2Filter)));
        }
    }
}

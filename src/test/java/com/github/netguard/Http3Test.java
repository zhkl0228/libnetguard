package com.github.netguard;

import cn.hutool.core.codec.Base64;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.udp.quic.netty.QuicSslContextWrapper;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.incubator.codec.http3.DefaultHttp3DataFrame;
import io.netty.incubator.codec.http3.DefaultHttp3HeadersFrame;
import io.netty.incubator.codec.http3.Http3;
import io.netty.incubator.codec.http3.Http3ClientConnectionHandler;
import io.netty.incubator.codec.http3.Http3DataFrame;
import io.netty.incubator.codec.http3.Http3Exception;
import io.netty.incubator.codec.http3.Http3HeadersFrame;
import io.netty.incubator.codec.http3.Http3RequestStreamInboundHandler;
import io.netty.incubator.codec.http3.Http3ServerConnectionHandler;
import io.netty.incubator.codec.quic.InsecureQuicTokenHandler;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicException;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamChannel;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import junit.framework.TestCase;
import net.luminis.http3.Http3Client;
import net.luminis.http3.impl.Http3ClientConnectionImpl;
import net.luminis.http3.server.Http3ApplicationProtocolFactory;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.PacketParser;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnector;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import javax.net.ssl.SSLEngine;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Http3Test extends TestCase {

    private static final byte[] CONTENT = "Hello World!\r\n".getBytes(CharsetUtil.US_ASCII);

    public void testNettyServer() throws Exception {
        NioEventLoopGroup group = new NioEventLoopGroup(1);
        SelfSignedCertificate cert = new SelfSignedCertificate();
        QuicSslContext sslContext = QuicSslContextBuilder.forServer(cert.key(), "", cert.cert())
                .applicationProtocols(Http3.supportedApplicationProtocols()).build();
        ChannelHandler codec = Http3.newQuicServerCodecBuilder()
                .sslContext(sslContext)
                .maxIdleTimeout(5000, TimeUnit.MILLISECONDS)
                .initialMaxData(10000000)
                .initialMaxStreamDataBidirectionalLocal(1000000)
                .initialMaxStreamDataBidirectionalRemote(1000000)
                .initialMaxStreamsBidirectional(100)
                .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
                .handler(new ChannelInitializer<QuicChannel>() {
                    @Override
                    protected void initChannel(QuicChannel ch) {
                        // Called for each connection
                        ch.pipeline().addLast(new Http3ServerConnectionHandler(
                                new ChannelInitializer<QuicStreamChannel>() {
                                    // Called for each request-stream,
                                    @Override
                                    protected void initChannel(QuicStreamChannel ch) {
                                        ch.pipeline().addLast(new Http3RequestStreamInboundHandler() {

                                            @Override
                                            protected void channelRead(
                                                    ChannelHandlerContext ctx, Http3HeadersFrame frame) {
                                                ReferenceCountUtil.release(frame);
                                            }

                                            @Override
                                            protected void channelRead(
                                                    ChannelHandlerContext ctx, Http3DataFrame frame) {
                                                ReferenceCountUtil.release(frame);
                                            }

                                            @Override
                                            protected void channelInputClosed(ChannelHandlerContext ctx) {
                                                Http3HeadersFrame headersFrame = new DefaultHttp3HeadersFrame();
                                                headersFrame.headers().status("404");
                                                headersFrame.headers().add("server", "netty");
                                                headersFrame.headers().addInt("content-length", CONTENT.length);
                                                ctx.write(headersFrame);
                                                ctx.writeAndFlush(new DefaultHttp3DataFrame(
                                                                Unpooled.wrappedBuffer(CONTENT)))
                                                        .addListener(QuicStreamChannel.SHUTDOWN_OUTPUT);
                                            }
                                        });
                                    }
                                }));
                    }
                }).build();
        try {
            Bootstrap bs = new Bootstrap();
            Channel channel = bs.group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(codec)
                    .bind(new InetSocketAddress(8443)).sync().channel();
            channel.closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    public void testNettyClient() throws Exception {
        URI uri = URI.create("https://quic.nginx.org/test");
        int port = uri.getPort();
        if (port <= 0) {
            port = Http3ClientConnectionImpl.DEFAULT_HTTP3_PORT;
        }
        NioEventLoopGroup group = new NioEventLoopGroup(1);

        try {
            QuicSslContext context = QuicSslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .applicationProtocols(Http3.supportedApplicationProtocols()).build();
            ChannelHandler codec = Http3.newQuicClientCodecBuilder()
                    .sslContext(new QuicSslContextWrapper(context, uri.getHost(), port))
                    .maxIdleTimeout(5000, TimeUnit.MILLISECONDS)
                    .initialMaxData(10000000)
                    .initialMaxStreamDataBidirectionalLocal(1000000)
                    .build();

            Bootstrap bs = new Bootstrap();
            Channel channel = bs.group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(codec)
                    .bind(0).sync().channel();

            QuicChannel quicChannel = QuicChannel.newBootstrap(channel)
                    .handler(new Http3ClientConnectionHandler())
                    .remoteAddress(new InetSocketAddress(uri.getHost(), port))
                    .connect()
                    .get();
            SSLEngine sslEngine = quicChannel.sslEngine();
            assertNotNull(sslEngine);
            System.out.println("applicationProtocol=" + sslEngine.getApplicationProtocol());

            QuicStreamChannel streamChannel = Http3.newRequestStream(quicChannel,
                    new Http3RequestStreamInboundHandler() {
                        @Override
                        protected void channelRead(ChannelHandlerContext ctx, Http3HeadersFrame frame) {
                            System.err.println(frame.headers());
                            ReferenceCountUtil.release(frame);
                        }

                        @Override
                        protected void channelRead(ChannelHandlerContext ctx, Http3DataFrame frame) {
                            System.err.print(frame.content().toString(CharsetUtil.US_ASCII));
                            ReferenceCountUtil.release(frame);
                        }

                        @Override
                        protected void channelInputClosed(ChannelHandlerContext ctx) {
                            ctx.close();
                            System.out.println("channelInputClosed");
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                            super.exceptionCaught(ctx, cause);
                            cause.printStackTrace(System.out);
                        }

                        @Override
                        protected void handleHttp3Exception(ChannelHandlerContext ctx, Http3Exception exception) {
                            super.handleHttp3Exception(ctx, exception);
                            exception.printStackTrace(System.out);
                        }

                        @Override
                        protected void handleQuicException(ChannelHandlerContext ctx, QuicException exception) {
                            super.handleQuicException(ctx, exception);
                            exception.printStackTrace(System.out);
                        }
                    }).sync().getNow();

            // Write the Header frame and send the FIN to mark the end of the request.
            // After this its not possible anymore to write any more data.
            Http3HeadersFrame frame = new DefaultHttp3HeadersFrame();
            String path = uri.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            frame.headers().method("GET").path(path)
                    .authority(uri.getHost() + ":" + port)
                    .scheme("https");
            streamChannel.writeAndFlush(frame)
                    .addListener(QuicStreamChannel.SHUTDOWN_OUTPUT).sync();

            // Wait for the stream channel and quic channel to be closed (this will happen after we received the FIN).
            // After this is done we will close the underlying datagram channel.
            streamChannel.closeFuture().sync();

            // After we received the response lets also close the underlying QUIC channel and datagram channel.
            quicChannel.close().sync();
            channel.close().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    public void testFlupkeServer() throws Exception {
        SysOutLogger logger = new SysOutLogger();
        logger.logDebug(true);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate peerCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.decode(CERT)));
        RootCert rootCert = RootCert.load();
        ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedBidirectionalStreams(50)
                .maxOpenPeerInitiatedUnidirectionalStreams(50)
                .build();
        ServerConnector.Builder builder = ServerConnector.builder();
        serverCertificate.getServerContext(rootCert).configServerConnector(builder);
        ServerConnector serverConnector = builder
                .withPort(20170)
                .withConfiguration(serverConnectionConfig)
                .withLogger(logger)
                .withPort(8443)
                .build();
        serverConnector.registerApplicationProtocol("h3", new Http3ApplicationProtocolFactory(new File("target/")));
        serverConnector.start();
        TimeUnit.HOURS.sleep(1);
    }

    public void testFlupkeClient() throws Exception {
        URI serverUrl = URI.create("https://quic.nginx.org/test");
        HttpRequest request = HttpRequest.newBuilder()
                .uri(serverUrl)
                .timeout(Duration.ofSeconds(30))
                .build();

        HttpClient client = Http3Client.newBuilder()
                .logger(new SysOutLogger())
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        HttpResponse<String> httpResponse = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(httpResponse.body());
    }

    private static final String CERT = "MIIFgTCCBGmgAwIBAgIQcE3nKOceYvQOhOwmZPsf/DANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFQNTAeFw0yNDA1MDgwMTAxMzRaFw0yNDA4MDYwMTAxMzNaMB4xHDAaBgNVBAMTE2Nsb3VkZmxhcmUtcXVpYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/l9pjH5Sbyc6qUSP3vAnjFilbferKW+Ka8cthNv9jLI349arf/VSWbrYSp/rbks88i1UB8ipz4T04PC2DNd4WVXoACmakfk9HXmPlGr3xCwlvX9oQAMrGatkwR4Js8407kNi0UmY9jvycqXW9t636A8F3RBuo2xK1MN+CqUE223PRWlTu1lVN+FK+sx6oiHHJj/9iOFwpb1Idpi2nkXdDKJEp6UQ+yI0aXgf/pwdQXBWCpu9vx1HeMDQYdYlh+cW2tMrAuXsvW+lL0gJy3KHx8UTZ5iWThUh+Xg59XG/1PPdTt8CrDyhknTYMQTpBovhWmHfOFhOltFawI5Qn2pPDAgMBAAGjggKRMIICjTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUTI6TiBr47S4b7esw6BSvmyGE8NkwHwYDVR0jBBgwFoAU1fyeDd8eyt0Il5duK8VfxSv17LgweAYIKwYBBQUHAQEEbDBqMDUGCCsGAQUFBzABhilodHRwOi8vb2NzcC5wa2kuZ29vZy9zL2d0czFwNS9SRF9GSWZmSWRlbzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMXA1LmRlcjA1BgNVHREELjAsghNjbG91ZGZsYXJlLXF1aWMuY29tghUqLmNsb3VkZmxhcmUtcXVpYy5jb20wIQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAHWeQIFAzA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3Jscy5wa2kuZ29vZy9ndHMxcDUvbDY3cDd2cUpNdzguY3JsMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHcA7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZsAAAGPVe9EhgAABAMASDBGAiEAkSkumeCDdBbKyH/5EcuOKf0d+7Uz2dqHDwSpxXKOo6kCIQCPKlajPFSGw0B7yOtj/3R5C7tewa8yckF0j6cSBh2i3AB1ABmYEHEJ8NZSLjCA0p4/ZLuDbijM+Q9Sju7fzko/FrTKAAABj1XvRN8AAAQDAEYwRAIgUG/vOiVe1wyH2ScePSAuqztqExp0T9dJqfjaV8IfKzwCIGtc/xGrWNpW5snAI8fzQdY3OTtmBSrsbI++0jpxrcUoMA0GCSqGSIb3DQEBCwUAA4IBAQB7+nunJo6tp4ajd5BVrUr4LHjhGA+hLrB3LcoGI994dOuEQrh0ehyvZnsK5qCSwcE2nusQvilT+yNQzT1yYDqzMZxjKM1dDy+jGbLjyMzcwRI70kSlRcm4APo8ahnFw+B4T8ZyiH9xSbG+/0npVqdNbFvavk2SWlMCGPdSE7Bj4D90KEE3RoqOaBQnfiPoPxx5rt17fY3RIlnFA41p1xzehmjfSFNBawDPipVi3+Xn5KwS9EWRdZyNo+QviHVH6iwRjCV/vKLZ87ej139XmBrWd9/B8l7X+W0iRo8z+0OG0SsucX4tZrx2CKJHksIU6GyEOwXsFJWs8LVt1CsYanbA";
    private final String applicationProtocol = "test";

    public void testServer() throws Exception {
        Logger.getLogger(PacketParser.class).setLevel(Level.DEBUG);
        SysOutLogger logger = new SysOutLogger();
        logger.logDebug(true);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate peerCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.decode(CERT)));
        if (peerCertificate == null) {
            QuicClientConnection connection = QuicClientConnection.newBuilder()
                    .uri(URI.create("https://cloudflare-quic.com"))
                    .applicationProtocol("h3")
                    .logger(logger)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();
            connection.connect();
            List<X509Certificate> chain = connection.getServerCertificateChain();
            peerCertificate = chain.get(0);
            System.out.println(Base64.encode(peerCertificate.getEncoded()));
        }
        {
            RootCert rootCert = RootCert.load();
            ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
            ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                    .maxOpenPeerInitiatedBidirectionalStreams(50)
                    .maxOpenPeerInitiatedUnidirectionalStreams(50)
                    .build();
            ServerConnector.Builder builder = ServerConnector.builder();
            serverCertificate.getServerContext(rootCert).configServerConnector(builder);
            ServerConnector serverConnector = builder
                    .withPort(20170)
                    .withConfiguration(serverConnectionConfig)
                    .withLogger(logger)
                    .build();
            serverConnector.registerApplicationProtocol(applicationProtocol, (protocol, quicConnection) -> {
                System.out.println("protocol=" + protocol + ", quicConnection=" + quicConnection);
                return new MyApplicationProtocolConnection(quicConnection);
            });
            serverConnector.start();
            TimeUnit.HOURS.sleep(1);
        }
    }

    public void testClient() throws Exception {
        Logger.getLogger(ServerCertificate.class).setLevel(Level.DEBUG);
        SysOutLogger logger = new SysOutLogger();
        logger.logDebug(false);
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        builder.applicationProtocol("h3");
        builder.applicationProtocol(applicationProtocol);
        QuicClientConnection connection = builder
                .uri(URI.create("https://127.0.0.1:20170"))
                .logger(logger)
                .noServerCertificateCheck()
                .build();
        connection.connect();
        System.out.println(connection.getServerCertificateChain());
        QuicStream quicStream = connection.createStream(true);
        try (OutputStream output = quicStream.getOutputStream()) {
            output.write("Hello".getBytes());
            output.flush();
        }
        try (InputStream input = quicStream.getInputStream()) {
            Inspector.inspect(IOUtils.toByteArray(input), "Response");
        }
        connection.close();
    }

    private static class MyApplicationProtocolConnection implements ApplicationProtocolConnection {

        private class Handler implements Runnable {
            private final QuicStream stream;

            public Handler(QuicStream stream) {
                this.stream = stream;
            }

            @Override
            public void run() {
                try (InputStream inputStream = stream.getInputStream(); OutputStream outputStream = stream.getOutputStream()) {
                    System.out.println(new String(IOUtils.toByteArray(inputStream)));
                    outputStream.write("Echo".getBytes());
                    outputStream.flush();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                } finally {
                    quicConnection.close();
                }
            }
        }

        private final QuicConnection quicConnection;

        public MyApplicationProtocolConnection(QuicConnection quicConnection) {
            this.quicConnection = quicConnection;
        }

        @Override
        public void acceptPeerInitiatedStream(QuicStream stream) {
            new Thread(new Handler(stream)).start();
        }
    }
}

package com.github.netguard;

import cn.hutool.core.codec.Base64;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import junit.framework.TestCase;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.PacketParser;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnector;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Http3Test extends TestCase {

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
                    .uri(URI.create("https://cloudflare-quic.com:443"))
                    .applicationProtocol("h3")
                    .logger(logger)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();
            connection.connect();
            List<X509Certificate> chain = connection.getServerCertificateChain();
            peerCertificate = chain.get(0);
            System.out.println(Base64.encode(peerCertificate.getEncoded()));
        }
        int port;
        {
            RootCert rootCert = RootCert.load();
            ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
            ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                    .maxOpenPeerInitiatedBidirectionalStreams(50)
                    .maxOpenPeerInitiatedUnidirectionalStreams(50)
                    .build();
            ServerConnector.Builder builder = ServerConnector.builder();
            serverCertificate.configKeyStore(rootCert, builder);
            ServerConnector serverConnector = builder
                    .withPort(20170)
                    .withConfiguration(serverConnectionConfig)
                    .withLogger(logger)
                    .build();
            port = serverConnector.getListenPort();
            System.out.println("port=" + port);
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
            Inspector.inspect(input.readAllBytes(), "Response");
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
                    System.out.println(new String(inputStream.readAllBytes()));
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

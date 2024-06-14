package com.github.netguard;

import cn.hutool.core.codec.Base64;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import junit.framework.TestCase;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.core.Role;
import net.luminis.quic.core.Version;
import net.luminis.quic.core.VersionHolder;
import net.luminis.quic.crypto.Aead;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.MissingKeysException;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.InitialPacket;
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
import java.nio.ByteBuffer;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
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
            port = serverConnector.getBindPort();
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
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                .uri(URI.create("https://127.0.0.1:20170"))
                .applicationProtocol(applicationProtocol)
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

    public void testQuicPacket() throws Exception {
        byte[] tmp = Base64.decode("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");
        tmp = Arrays.copyOf(tmp, 1200);
        ByteBuffer data = ByteBuffer.wrap(tmp);
        data.mark();

        {
            int flags = data.get();
            assertTrue((flags & 0x80) == 0x80);
            int version = data.getInt();
            Version quicVersion = Version.parse(version);
            int dcidLength = data.get() & 0xff;
            byte[] dcid = new byte[dcidLength];
            data.get(dcid);
            int type = (flags & 0x30) >> 4;
            assertTrue(InitialPacket.isInitial(type, quicVersion));
            InitialPacket packet = new InitialPacket(quicVersion);
            ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(quicVersion), Role.Server, null, new NullLogger());
            connectionSecrets.computeInitialKeys(dcid);
            try {
                data.reset();
                Aead aead = connectionSecrets.getPeerAead(packet.getEncryptionLevel());
                packet.parse(data, aead, 0, new NullLogger(), 0);
                System.out.println(packet);
                CryptoFrame cryptoFrame = (CryptoFrame) packet.getFrames().get(0);
                Inspector.inspect(cryptoFrame.getStreamData(), "cryptoFrame");
            } catch (MissingKeysException e) {
                // Impossible, as initial keys have just been computed.
                throw new RuntimeException(e);
            }
        }
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

package com.github.netguard;

import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import junit.framework.TestCase;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnector;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

public class Http3Test extends TestCase {

    public void testClient() throws Exception {
        Logger.getLogger(ServerCertificate.class).setLevel(Level.DEBUG);
        SysOutLogger logger = new SysOutLogger();
        logger.logDebug(false);
        X509Certificate peerCertificate;
        {
            QuicClientConnection connection = QuicClientConnection.newBuilder()
                    .uri(URI.create("https://cloudflare-quic.com:443"))
                    .applicationProtocol("h3")
                    .logger(logger)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();
            connection.connect();
            List<X509Certificate> chain = connection.getServerCertificateChain();
            peerCertificate = chain.get(0);
        }
        final String applicationProtocol = "test";
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
                    .withPort(0)
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
        }
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                .uri(URI.create("https://127.0.0.1:" + port))
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

package com.github.netguard.vpn.ssl;

import cn.banny.utils.IOUtils;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

class PeerCertificateFetcher implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(PeerCertificateFetcher.class);

    private final X509Certificate rootCert;
    private final PrivateKey privateKey;
    private final InetSocketAddress server;
    private final int timeout;
    private final Packet packet;
    private final HandshakeStatus failedStatus;

    private final ServerSocket serverSocket;

    public PeerCertificateFetcher(X509Certificate rootCert, PrivateKey privateKey, InetSocketAddress server, int timeout, Packet packet, HandshakeStatus failedStatus) throws IOException {
        this.rootCert = rootCert;
        this.privateKey = privateKey;
        this.server = server;
        this.timeout = timeout;
        this.packet = packet;
        this.failedStatus = failedStatus;

        this.serverSocket = SSLProxy.addressHostNameMap.containsKey(server) ? null : ServerSocketFactory.getDefault().createServerSocket(0);
    }

    int getServerPort() {
        return serverSocket == null ? 0 : serverSocket.getLocalPort();
    }

    @Override
    public void run() {
        if (serverSocket == null) {
            tryCertificate(null);
            return;
        }

        try (Socket socket = serverSocket.accept()) {
            try (InputStream inputStream = socket.getInputStream()) {
                DataInput dataInput = new DataInputStream(inputStream);
                String hostName = ExtensionServerName.parseServerNames(dataInput, server);
                if (hostName == null) {
                    SSLProxy.handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                } else {
                    SSLProxy.addressHostNameMap.put(server, hostName);
                    tryCertificate(hostName);
                }
            }
        } catch (Exception e) {
            log.trace("handshake failed: packet={}", packet, e);
        } finally {
            IOUtils.close(serverSocket);
        }
    }

    private void tryCertificate(String hostName) {
        try (Socket socket = SSLProxy.connectServer(new ServerCertificateNotifier() {
            @Override
            public void handshakeCompleted(ServerCertificate serverCertificate) {
                try {
                    serverCertificate.createSSLContext(rootCert, privateKey, server);
                } catch (Exception e) {
                    log.warn("create ssl context failed", e);
                }
            }
        }, timeout, packet, hostName)) {
            log.debug("handshake success: socket={}", socket);
            SSLProxy.handshakeStatusMap.put(server, HandshakeStatus.success);
        } catch (Exception e) {
            log.trace("handshake failed: {}", server, e);
            SSLProxy.handshakeStatusMap.put(server, failedStatus);
        }
    }
}

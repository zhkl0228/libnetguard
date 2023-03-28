package com.github.netguard.vpn.ssl;

import cn.banny.utils.IOUtils;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
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

    static Allowed tryPeerCertificate(X509Certificate rootCert, PrivateKey privateKey, InetSocketAddress server, int timeout, Packet packet, HandshakeStatus failedStatus,
                                      InspectorVpn vpn) throws IOException {
        String hostName = SSLProxy.addressHostNameMap.get(server);
        if (hostName != null) {
            SSLContext serverContext = ServerCertificate.getSSLContext(server, hostName);
            if (serverContext != null) {
                ServerCertificate.serverSSLContextMap.put(server, serverContext);
                SSLProxy.handshakeStatusMap.put(server, HandshakeStatus.success);
                log.debug("tryPeerCertificate context={}, server={}, hostName={}", serverContext, server, hostName);
                return new SSLProxy(vpn, serverContext, packet, timeout).redirect();
            }
        }

        PeerCertificateFetcher peerCertificateFetcher = new PeerCertificateFetcher(rootCert, privateKey, server, timeout, packet, failedStatus,
                hostName);
        return peerCertificateFetcher.redirect();
    }

    private PeerCertificateFetcher(X509Certificate rootCert, PrivateKey privateKey, InetSocketAddress server, int timeout, Packet packet, HandshakeStatus failedStatus,
                                   String hostName) throws IOException {
        this.rootCert = rootCert;
        this.privateKey = privateKey;
        this.server = server;
        this.timeout = timeout;
        this.packet = packet;
        this.failedStatus = failedStatus;
        this.hostName = hostName;

        this.serverSocket = hostName != null ? null : ServerSocketFactory.getDefault().createServerSocket(0);

        Thread thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }

    private String hostName;

    @Override
    public void run() {
        if (serverSocket == null) {
            tryCertificate();
            return;
        }

        try (Socket socket = serverSocket.accept()) {
            try (InputStream inputStream = socket.getInputStream()) {
                DataInput dataInput = new DataInputStream(inputStream);
                this.hostName = ExtensionServerName.parseServerNames(dataInput, server);
                if (hostName == null) {
                    SSLProxy.handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                } else {
                    SSLProxy.addressHostNameMap.put(server, hostName);
                    tryCertificate();
                }
            }
        } catch (Exception e) {
            log.trace("handshake failed: packet={}", packet, e);
        } finally {
            IOUtils.close(serverSocket);
        }
    }

    private void tryCertificate() {
        try (Socket socket = SSLProxy.connectServer(new ServerCertificateNotifier() {
            @Override
            public void handshakeCompleted(ServerCertificate serverCertificate) {
                try {
                    serverCertificate.createSSLContext(rootCert, privateKey, server, hostName);
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

    private Allowed redirect() {
        int port = serverSocket == null ? 0 : serverSocket.getLocalPort();
        if (port == 0) {
            return null;
        } else {
            return new Allowed("127.0.0.1", port);
        }
    }

}

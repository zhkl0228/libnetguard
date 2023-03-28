package com.github.netguard.vpn.ssl;

import cn.banny.utils.IOUtils;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxyV2 implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxyV2.class);

    private static final int SERVER_SO_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(1);

    public static Allowed create(final InspectorVpn vpn, final X509Certificate rootCert, final PrivateKey privateKey, final Packet packet, final int timeout) {
        try {
            log.debug("create mitm packet={}", packet);
            IPacketCapture packetCapture = vpn.getPacketCapture();
            SSLProxyV2 proxy = new SSLProxyV2(rootCert, privateKey, packetCapture, packet, timeout);
            Allowed allowed = proxy.redirect();
            log.debug("create mitm packet={}, allowed={}", packet, allowed);
            return allowed;
        } catch (IOException e) {
            log.warn("create SSLProxy failed", e);
            return null;
        }
    }

    private final X509Certificate rootCert;
    private final PrivateKey privateKey;

    private final Packet packet;
    private final IPacketCapture packetCapture;
    private final int timeout;
    private final ServerSocket serverSocket;
    private final SSLSocket secureSocket;

    private SSLProxyV2(X509Certificate rootCert, PrivateKey privateKey, IPacketCapture packetCapture, Packet packet, int timeout) throws IOException {
        this.rootCert = rootCert;
        this.privateKey = privateKey;

        this.packetCapture = packetCapture;
        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = null;
        this.hostName = null;

        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLocalHost());
        this.serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);

        Thread thread = new Thread(this, "Proxy for " + packet);
        thread.setDaemon(true);
        thread.start();
    }

    private final String hostName;

    private SSLProxyV2(IPacketCapture packetCapture, Packet packet, int timeout, SSLContext context, SSLSocket secureSocket, String hostName) throws IOException {
        this.rootCert = null;
        this.privateKey = null;

        this.packetCapture = packetCapture;
        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = secureSocket;
        this.hostName = hostName;

        SSLServerSocketFactory factory = context.getServerSocketFactory();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLocalHost());
        this.serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);

        Thread thread = new Thread(this, "SSLProxy for " + packet);
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        InetSocketAddress remote = packet.createServerAddress();
        try (Socket local = serverSocket.accept()) {
            try (InputStream localIn = local.getInputStream(); OutputStream localOut = local.getOutputStream()) {
                if (secureSocket != null) {
                    handleSSLSocket(remote, localIn, localOut, local, secureSocket, hostName);
                } else {
                    handleSocket(remote, localIn, localOut, local);
                }
            }
        } catch (IOException e) {
            if (hostName == null) {
                log.trace("proxy failed: serverSocket={}, packet={}", serverSocket, packet, e);
            } else {
                log.debug("proxy failed: hostName={}, serverSocket={}, packet={}", hostName, serverSocket, packet, e);
            }
        } catch (Exception e) {
            log.warn("proxy failed: hostName={}, serverSocket={}, packet={}", hostName, serverSocket, packet, e);
        } finally {
            IOUtils.close(secureSocket);
            IOUtils.close(serverSocket);
        }
    }

    private void handleSSLSocket(InetSocketAddress remote, InputStream localIn, OutputStream localOut, Socket local, SSLSocket socket, String hostName) throws IOException, InterruptedException {
        log.debug("ssl proxy remote={}, socket={}, local={}, hostName={}", remote, socket, local, hostName);
        try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
            doForward(localIn, localOut, local, socketIn, socketOut, socket, packetCapture, hostName);
        }
    }

    private static void doForward(InputStream localIn, OutputStream localOut, Socket local, InputStream socketIn, OutputStream socketOut, Socket socket, IPacketCapture packetCapture, String hostName) throws InterruptedException {
        log.debug("doForward local={}, socket={}, hostName={}", local, socket, hostName);
        InetSocketAddress client = (InetSocketAddress) local.getRemoteSocketAddress();
        InetSocketAddress server = (InetSocketAddress) socket.getRemoteSocketAddress();
        if (packetCapture != null) {
            packetCapture.onSSLProxyEstablish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), hostName);
        }
        CountDownLatch countDownLatch = new CountDownLatch(2);
        new StreamForward(localIn, socketOut, true, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, local, packetCapture, hostName);
        new StreamForward(socketIn, localOut, false, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, socket, packetCapture, hostName);
        countDownLatch.await();

        if (packetCapture != null) {
            packetCapture.onSSLProxyFinish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), hostName);
        }
    }

    private void handleSocket(InetSocketAddress remote, InputStream localIn, OutputStream localOut, Socket local) throws Exception {
        DataInput dataInput = new DataInputStream(localIn);
        ClientHelloRecord record = ExtensionServerName.parseServerNames(dataInput, remote);
        log.debug("proxy remote={}, record={}, local={}", remote, record, local);
        if (record.hostName == null) {
            try (Socket socket = new Socket()) {
                socket.connect(remote, timeout);
                try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                    socketOut.write(record.readData);
                    socketOut.flush();
                    doForward(localIn, localOut, local, socketIn, socketOut, socket, null, null);
                }
            }
        } else {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustManagers = InsecureTrustManagerFactory.INSTANCE.getTrustManagers();
            context.init(null, trustManagers, null);
            SSLSocketFactory factory = context.getSocketFactory();
            Socket app = null;
            SSLSocket secureSocket = null;
            try {
                app = new Socket();
                app.connect(remote, timeout);
                secureSocket = (SSLSocket) factory.createSocket(app, record.hostName, remote.getPort(), true);
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                secureSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                    @Override
                    public void handshakeCompleted(HandshakeCompletedEvent event) {
                        try {
                            peerCertificate = (X509Certificate) event.getPeerCertificates()[0];
                            SSLSession session = event.getSession();
                            log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                        } catch (SSLPeerUnverifiedException e) {
                            log.debug("handshakeCompleted failed", e);
                        } finally {
                            countDownLatch.countDown();
                        }
                    }
                });
                secureSocket.startHandshake();
                countDownLatch.await();
                if (peerCertificate == null) {
                    throw new IOException("Handshake failed with: " + record.hostName + ", remote=" + remote);
                }

                ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
                SSLContext serverContext = serverCertificate.createSSLContext(rootCert, privateKey);
                SSLProxyV2 proxy = new SSLProxyV2(packetCapture, packet, timeout, serverContext, secureSocket, record.hostName);
                try (Socket socket = SocketFactory.getDefault().createSocket("127.0.0.1", proxy.serverSocket.getLocalPort())) {
                    try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                        socketOut.write(record.readData);
                        socketOut.flush();
                        doForward(localIn, localOut, local, socketIn, socketOut, socket, null, null);
                    }
                }
            } catch (IOException e) {
                IOUtils.close(app);
                IOUtils.close(secureSocket);
                throw e;
            }
        }
    }

    private X509Certificate peerCertificate;

    private Allowed redirect() {
        return new Allowed("127.0.0.1", serverSocket.getLocalPort());
    }

}
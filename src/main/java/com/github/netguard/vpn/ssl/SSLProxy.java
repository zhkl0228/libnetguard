package com.github.netguard.vpn.ssl;

import cn.banny.utils.IOUtils;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxy implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxy.class);

    private SSLSocket socket;
    private final SSLServerSocket serverSocket;
    private final Packet packet;
    private final InspectorVpn vpn;

    static final Map<InetSocketAddress, HandshakeStatus> handshakeStatusMap = new ConcurrentHashMap<>();

    public static Allowed create(final InspectorVpn vpn, final X509Certificate rootCert, final PrivateKey privateKey, final Packet packet, final int timeout) {
        try {
            final InetSocketAddress server = packet.createServerAddress();
            final HandshakeStatus status = handshakeStatusMap.get(server);
            if (status == null || status == HandshakeStatus.failed1) {
                handshakeStatusMap.put(server, HandshakeStatus.handshaking);
                return PeerCertificateFetcher.tryPeerCertificate(rootCert, privateKey, server, timeout, packet, status == null ? HandshakeStatus.failed1 : HandshakeStatus.failed2,
                        vpn);
            }
            switch (status) {
                case handshaking: // 正在进行SSL握手
                    return null;
                case failed2: // 两次握手失败：连接失败，或者不是SSL协议
                case not_tls:
                    return new Allowed(); // Disable mitm
                case success: // 握手成功
                    SSLContext serverContext = ServerCertificate.getSSLContext(server, null);
                    if (serverContext != null) {
                        return new SSLProxy(vpn, serverContext, packet, timeout).redirect();
                    }
                default:
                    throw new IllegalStateException("server=" + server + ", status=" + status);
            }
        } catch (IOException e) {
            throw new IllegalStateException("mitm failed", e);
        }
    }

    private final int timeout;

    SSLProxy(InspectorVpn vpn, SSLContext serverContext, Packet packet, int timeout) throws IOException {
        this.vpn = vpn;
        this.packet = packet;
        this.timeout = timeout;
        this.serverSocket = startSSLServerSocket(serverContext, this, packet);
    }

    static final int SERVER_SO_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);

    private static SSLServerSocket startSSLServerSocket(SSLContext serverContext, SSLProxy proxy, Packet packet) throws IOException {
        SSLServerSocketFactory factory = serverContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(0);
        serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);

        Thread thread = new Thread(proxy, packet.toString());
        thread.setDaemon(true);
        thread.start();
        return serverSocket;
    }

    static SSLSocket connectServer(final ServerCertificateNotifier notifier, int timeout, Packet packet, String host) throws Exception {
        Socket app = null;
        SSLSocket socket = null;
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustManagers = InsecureTrustManagerFactory.INSTANCE.getTrustManagers();
            context.init(null, trustManagers, null);

            app = new Socket();
            app.bind(null);
            app.setSoTimeout(timeout);
            InetSocketAddress server = packet.createServerAddress();
            app.connect(server, 5000);

            if (host == null) {
                host = addressHostNameMap.get(server);
            }
            if (host == null) {
                host = packet.daddr;
            } else {
                packet.hostName = host;
            }
            socket = (SSLSocket) context.getSocketFactory().createSocket(app, host, packet.dport, true);
            final CountDownLatch countDownLatch = new CountDownLatch(1);
            socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                @Override
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    try {
                        X509Certificate peerCertificate = (X509Certificate) event.getPeerCertificates()[0];
                        if (notifier != null) {
                            notifier.handshakeCompleted(new ServerCertificate(peerCertificate));
                        }
                        countDownLatch.countDown();
                        SSLSession session = event.getSession();
                        log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                    } catch (SSLPeerUnverifiedException e) {
                        log.warn("handshakeCompleted failed", e);
                    }
                }
            });
            log.debug("connectServer socket={}", socket);
            socket.startHandshake();
            if (!countDownLatch.await(timeout, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("handshake failed");
            }
            app.setSoTimeout(0);
            return socket;
        } catch (Exception e) {
            IOUtils.close(app);
            IOUtils.close(socket);
            throw e;
        }
    }

    final synchronized Allowed redirect() {
        return new Allowed("127.0.0.1", serverSocket.getLocalPort());
    }

    static final Map<InetSocketAddress, String> addressHostNameMap = new ConcurrentHashMap<>();

    private SSLSocket local;

    @Override
    public void run() {
        Runnable runnable = null;
        try {
            local = (SSLSocket) serverSocket.accept();
            local.startHandshake();
            this.socket = connectServer(null, timeout, packet, null);
            local.setSoTimeout(timeout);
            log.debug("connect ssl: local={}, socket={}, packet={}", local, socket, packet);

            final InetSocketAddress client = (InetSocketAddress) local.getRemoteSocketAddress();
            final InetSocketAddress server = (InetSocketAddress) socket.getRemoteSocketAddress();
            InputStream localIn = local.getInputStream(); // 这里异常可能是证书没有被信任
            OutputStream localOut = local.getOutputStream();
            InputStream socketIn = socket.getInputStream();
            OutputStream socketOut = socket.getOutputStream();

            IPacketCapture packetCapture = vpn.getPacketCapture();
            if (packetCapture != null) {
                packetCapture.onSSLProxyEstablish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), packet.hostName);
            }
            final CountDownLatch countDownLatch = new CountDownLatch(2);
            new StreamForward(localIn, socketOut, true, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, local, packetCapture);
            new StreamForward(socketIn, localOut, false, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, socket, packetCapture);
            runnable = new Runnable() {
                @Override
                public void run() {
                    try {
                        countDownLatch.await();

                        IPacketCapture capture = vpn.getPacketCapture();
                        if (capture != null) {
                            capture.onSSLProxyFinish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort());
                        }
                    } catch (InterruptedException ignored) {
                    } finally {
                        IOUtils.close(socket);
                        IOUtils.close(local);
                    }
                }
            };
        } catch (Exception e) {
            log.trace("accept failed: {}, local_port={}", packet, serverSocket.getLocalPort(), e);

            IOUtils.close(socket);
            IOUtils.close(local);
        } finally {
            IOUtils.close(serverSocket);
        }

        if (runnable != null) {
            runnable.run();
        }
    }

}

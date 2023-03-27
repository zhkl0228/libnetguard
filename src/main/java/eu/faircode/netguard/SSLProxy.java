package eu.faircode.netguard;

import cn.banny.auxiliary.Inspector;
import cn.banny.utils.IOUtils;
import com.fuzhu8.tcpcap.kraken.ssl.ExtensionType;
import com.fuzhu8.tcpcap.kraken.ssl.Version;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.DefaultHandshake;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.Handshake;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.HandshakeType;
import com.fuzhu8.tcpcap.kraken.ssl.record.ContentType;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.ssl.ServerCertificate;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.apache.commons.codec.binary.Hex;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxy implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxy.class);

    private enum HandshakeStatus {
        handshaking, // 正在握手
        failed1, // 握手失败一次
        failed2, // 握手失败两次
        success, // 握手成功,
        not_tls // 不是 TLS 协议
    }

    private SSLSocket socket;
    private final SSLServerSocket serverSocket;
    private final Packet packet;
    private final InspectorVpn vpn;

    private static final Map<InetSocketAddress, HandshakeStatus> handshakeStatusMap = new ConcurrentHashMap<>();

    static Allowed create(final InspectorVpn vpn, final X509Certificate rootCert, final PrivateKey privateKey, final Packet packet, final int timeout) {
        try {
            final InetSocketAddress server = packet.createServerAddress();
            final HandshakeStatus status = handshakeStatusMap.get(server);
            if (status == null || status == HandshakeStatus.failed1) {
                handshakeStatusMap.put(server, HandshakeStatus.handshaking);
                HandshakeThread handshakeThread = new HandshakeThread(rootCert, privateKey, server, timeout, packet, status == null ? HandshakeStatus.failed1 : HandshakeStatus.failed2);
                Thread thread = new Thread(handshakeThread);
                thread.setDaemon(true);
                thread.start();
                int port = handshakeThread.getServerPort();
                if (port == 0) {
                    return null;
                } else {
                    return new Allowed("127.0.0.1", port);
                }
            }
            switch (status) {
                case handshaking: // 正在进行SSL握手
                    return null;
                case failed2: // 两次握手失败：连接失败，或者不是SSL协议
                case not_tls:
                    return new Allowed(); // Disable mitm
                case success: // 握手成功
                    SSLContext serverContext = ServerCertificate.getSSLContext(server);
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

    private SSLProxy(InspectorVpn vpn, SSLContext serverContext, Packet packet, int timeout) throws IOException {
        this.vpn = vpn;
        this.packet = packet;
        this.timeout = timeout;
        this.serverSocket = startSSLServerSocket(serverContext, this, packet);
    }

    private static final int SERVER_SO_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);

    private static SSLServerSocket startSSLServerSocket(SSLContext serverContext, SSLProxy proxy, Packet packet) throws IOException {
        SSLServerSocketFactory factory = serverContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(0);
        serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);

        Thread thread = new Thread(proxy, packet.toString());
        thread.setDaemon(true);
        thread.start();
        return serverSocket;
    }

    private interface ServerCertificateNotifier {
        void handshakeCompleted(ServerCertificate serverCertificate);
    }

    private static SSLSocket connectServer(final ServerCertificateNotifier notifier, int timeout, Packet packet, String host) throws Exception {
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

    private Throwable socketException;

    private static final Map<InetSocketAddress, String> addressHostNameMap = new ConcurrentHashMap<>();

    private static class HandshakeThread implements Runnable {
        private final X509Certificate rootCert;
        private final PrivateKey privateKey;
        private final InetSocketAddress server;
        private final int timeout;
        private final Packet packet;
        private final HandshakeStatus status;

        private final ServerSocket serverSocket;

        public HandshakeThread(X509Certificate rootCert, PrivateKey privateKey, InetSocketAddress server, int timeout, Packet packet, HandshakeStatus status) throws IOException {
            this.rootCert = rootCert;
            this.privateKey = privateKey;
            this.server = server;
            this.timeout = timeout;
            this.packet = packet;
            this.status = status;

            this.serverSocket = addressHostNameMap.containsKey(server) ? null : ServerSocketFactory.getDefault().createServerSocket(0);
        }

        int getServerPort() {
            return serverSocket == null ? 0 : serverSocket.getLocalPort();
        }

        private Version getVersion(short version) {
            Version tlsVer = Version.NONE;
            for (Version ver : Version.values()) {
                if (ver.getValue() == version) {
                    tlsVer = ver;
                    break;
                }
            }
            return tlsVer;
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
                    byte contentType = dataInput.readByte();
                    if (contentType != ContentType.Handshake.getValue()) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Not handshake record: contentType=0x%x, server=%s", contentType, server));
                        }
                        handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                        return;
                    }
                    short version = dataInput.readShort();
                    Version tlsVer = getVersion(version);
                    if (tlsVer == Version.NONE || tlsVer == Version.MM_TLS) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Tls version=0x%x, server=%s", version, server));
                        }
                        handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                        return;
                    }
                    int length = dataInput.readUnsignedShort();
                    if(length >= 0x800) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Tls length=0x%x, server=%s", length, server));
                        }
                        handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                        return;
                    }

                    byte[] data = new byte[length];
                    dataInput.readFully(data);
                    try {
                        Handshake handshake = DefaultHandshake.parseHandshake(new ChainBuffer(data));
                        if (handshake.getType() != HandshakeType.ClientHello) {
                            log.debug("Not tls: handshakeType={}, server={}", handshake.getType(), server);
                            handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                            return;
                        }

                        Buffer buffer = handshake.getBuffer();
                        version = buffer.getShort();
                        tlsVer = getVersion(version);
                        if (tlsVer == Version.NONE || tlsVer == Version.MM_TLS) {
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("Tls handshake version=0x%x, server=%s", version, server));
                            }
                            handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                            return;
                        }
                        byte[] clientRandom = new byte[32];
                        buffer.gets(clientRandom);
                        byte[] sessionId = new byte[buffer.get() & 0xff];
                        buffer.gets(sessionId);
                        int cipherSuitesLength = buffer.getUnsignedShort() / 2;
                        log.debug("handleClientHello sessionIdLength={}, cipherSuitesLength={}", sessionId.length, cipherSuitesLength);
                        buffer.skip(cipherSuitesLength * 2); // skip cipher suites
                        buffer.skip(buffer.get()); // compression methods
                        if (buffer.readableBytes() < 1) {
                            log.debug("Not tls: extension data is empty: server={}", server);
                            handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                            return;
                        }
                        int extensionLength = buffer.getUnsignedShort();
                        byte[] extensionData = new byte[extensionLength];
                        buffer.gets(extensionData);

                        buffer = new ChainBuffer(extensionData); // extensionData

                        List<String> serverNames = new ArrayList<>(3);
                        while(buffer.readableBytes() > 0) {
                            short type = buffer.getShort();
                            length = buffer.getUnsignedShort();
                            data = new byte[length];
                            buffer.gets(data);

                            if (type == ExtensionType.EXT_SERVER_NAME.getType()) {
                                Buffer nb = new ChainBuffer(data);
                                nb.getUnsignedShort(); // name length
                                byte nameType = nb.get();
                                if (nameType == 0) {
                                    int nameLength = nb.getUnsignedShort();
                                    String name = nb.getString(nameLength, StandardCharsets.UTF_8);
                                    serverNames.add(name);
                                } else {
                                    log.warn("Unsupported name type: {}, data={}, server={}", nameType, Hex.encodeHexString(data), server);
                                }
                            }
                            if(log.isDebugEnabled()) {
                                log.trace(Inspector.inspectString(data, "parseExtensions type=0x" + Integer.toHexString(type) + ", length=" + length));
                            }
                        }
                        log.debug("parseExtensions names={}, server={}", serverNames, server);

                        if (serverNames.isEmpty()) {
                            log.debug("Not tls: extension name is empty: server={}", server);
                            handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                            return;
                        }

                        String hostName = serverNames.get(0);
                        addressHostNameMap.put(server, hostName);

                        tryCertificate(hostName);
                    } catch (IllegalArgumentException e) {
                        log.debug("Not tls: server={}", server, e);
                        handshakeStatusMap.put(server, HandshakeStatus.not_tls);
                    }
                }
            } catch (Exception e) {
                log.trace("handshake failed: packet={}", packet, e);
            } finally {
                IOUtils.close(serverSocket);
            }
        }

        private void tryCertificate(String hostName) {
            try (Socket socket = connectServer(new ServerCertificateNotifier() {
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
                handshakeStatusMap.put(server, HandshakeStatus.success);
            } catch (Exception e) {
                log.trace("handshake failed: {}", server, e);
                handshakeStatusMap.put(server, status);
            }
        }
    }

    private class StreamForward implements Runnable {
        private final InputStream inputStream;
        private final OutputStream outputStream;
        private final boolean send;
        private final String clientIp, serverIp;
        private final int clientPort, serverPort;
        private final CountDownLatch countDownLatch;
        private final Socket socket;
        StreamForward(InputStream inputStream, OutputStream outputStream, boolean send, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket) {
            this.inputStream = inputStream;
            this.outputStream = outputStream;
            this.send = send;
            this.clientIp = clientIp;
            this.serverIp = serverIp;
            this.clientPort = clientPort;
            this.serverPort = serverPort;
            this.countDownLatch = countDownLatch;
            this.socket = socket;

            Thread thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
        }
        @Override
        public void run() {
            doForward();
        }

        private void doForward() {
            try {
                byte[] buf = new byte[socket.getReceiveBufferSize()];
                int read;
                while (socketException == null) {
                    try {
                        while ((read = inputStream.read(buf)) != -1) {
                            outputStream.write(buf, 0, read);
                            outputStream.flush();

                            IPacketCapture packetCapture = vpn.getPacketCapture();
                            if (packetCapture != null) {
                                if (send) {
                                    packetCapture.onSSLProxyTX(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                                } else {
                                    packetCapture.onSSLProxyRX(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                                }
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug(Inspector.inspectString(Arrays.copyOf(buf, read), socket.toString()));
                                }
                            }
                        }
                        break;
                    } catch(SocketTimeoutException ignored) {}
                }
            } catch (SSLHandshakeException e) {
                log.info(String.format("handshake with %s/%d failed: {}", serverIp, serverPort), e.getMessage());
                socketException = e;
            } catch (Throwable e) {
                log.trace("stream forward exception: socket={}", socket, e);
                socketException = e;
            } finally {
                IOUtils.close(inputStream);
                IOUtils.close(outputStream);
                countDownLatch.countDown();
            }
        }
    }

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
            new StreamForward(localIn, socketOut, true, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, local);
            new StreamForward(socketIn, localOut, false, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, socket);
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

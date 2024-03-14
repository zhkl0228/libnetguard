package com.github.netguard.vpn.ssl;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.net.DefaultTrustManager;
import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.github.netguard.vpn.ssl.h2.Http2Session;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxyV2 implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxyV2.class);

    private static final int SERVER_SO_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(1);

    public static Allowed create(final InspectorVpn vpn, RootCert rootCert, final Packet packet, final int timeout) {
        try {
            log.debug("create tcp proxy packet={}", packet);
            SSLProxyV2 proxy = new SSLProxyV2(vpn, rootCert, packet, timeout);
            Allowed allowed = proxy.redirect();
            log.debug("create tcp proxy packet={}, allowed={}", packet, allowed);
            return allowed;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void create(final InspectorVpn vpn, RootCert rootCert, final Packet packet, final int timeout, Socket socket) {
        try {
            log.debug("create tcp proxy packet={}", packet);
            new SSLProxyV2(vpn, rootCert, packet, timeout, socket);
            log.debug("create tcp proxy packet={}", packet);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private final InspectorVpn vpn;
    private final RootCert rootCert;

    private final Packet packet;
    private final int timeout;
    private final ServerSocket serverSocket;
    private final SSLSocket secureSocket;
    private final Socket acceptedSocket;

    private SSLProxyV2(InspectorVpn vpn, RootCert rootCert, Packet packet, int timeout, Socket socket) throws IOException {
        this.vpn = vpn;
        this.rootCert = rootCert;

        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = null;
        this.hostName = null;
        this.applicationProtocol = null;
        this.allowFilterH2 = false;
        this.applicationLayerProtocols = Collections.emptyList();

        this.serverSocket = null;
        this.acceptedSocket = socket;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Thread thread = new Thread(this, "Proxy for " + packet + " " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    private SSLProxyV2(InspectorVpn vpn, RootCert rootCert, Packet packet, int timeout) throws IOException {
        this.vpn = vpn;
        this.rootCert = rootCert;

        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = null;
        this.hostName = null;
        this.applicationProtocol = null;
        this.allowFilterH2 = false;
        this.applicationLayerProtocols = Collections.emptyList();

        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLoopbackAddress());
        this.serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);
        this.acceptedSocket = null;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Thread thread = new Thread(this, "Proxy for " + packet + " " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    private final String hostName;
    private final String applicationProtocol;
    private final boolean allowFilterH2;
    private final List<String> applicationLayerProtocols;

    private SSLProxyV2(InspectorVpn vpn, Packet packet, int timeout, SSLContext context, SSLSocket secureSocket,
                       ClientHelloRecord record, String applicationProtocol, boolean allowFilterH2) throws IOException {
        this.vpn = vpn;
        this.rootCert = null;

        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = secureSocket;
        this.hostName = record.hostName;
        this.applicationProtocol = applicationProtocol;
        this.allowFilterH2 = allowFilterH2;
        this.applicationLayerProtocols = record.applicationLayerProtocols;

        SSLServerSocketFactory factory = context.getServerSocketFactory();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLoopbackAddress());
        this.serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);
        this.acceptedSocket = null;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Thread thread = new Thread(this, "SSLProxy for " + packet + " " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        InetSocketAddress remote = packet.createServerAddress();
        try (Socket local = (serverSocket == null ? acceptedSocket : serverSocket.accept())) {
            try (InputStream localIn = local.getInputStream(); OutputStream localOut = local.getOutputStream()) {
                if (packet.isInstallRootCert()) {
                    downloadRootCert(localIn, localOut);
                } else {
                    if (secureSocket != null) {
                        handleSSLSocket(remote, localIn, localOut, local, secureSocket, hostName);
                    } else {
                        handleSocket(remote, localIn, localOut, local);
                    }
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
            IoUtil.close(secureSocket);
            IoUtil.close(serverSocket);
        }
    }

    private void downloadRootCert(InputStream localIn, OutputStream localOut) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(localIn));
        String line;
        String userAgentString = null;
        while ((line = reader.readLine()) != null) {
            log.debug("installRootCert: userAgent={}, line={}", userAgentString, line);
            if (line.toLowerCase().startsWith("user-agent")) {
                int index = line.indexOf(':');
                if (index != -1) {
                    userAgentString = line.substring(index + 1).trim();
                }
            }
            if (line.isEmpty()) {
                break;
            }
        }
        String pem = rootCert.pem;
        StringBuilder builder = new StringBuilder();
        builder.append("HTTP/1.1 200 OK\r\n");
        builder.append(HttpHeaderNames.CONNECTION).append(": close\r\n");
        builder.append(HttpHeaderNames.PRAGMA).append(": no-cache\r\n");
        builder.append(HttpHeaderNames.CONTENT_TYPE).append(": application/x-pem-file\r\n");
        builder.append(HttpHeaderNames.CONTENT_LENGTH).append(": ").append(pem.length()).append("\r\n");
        builder.append(HttpHeaderNames.SERVER).append(": ").append(getClass().getSimpleName()).append("\r\n");

        {
            String fileName = "NetGuard.pem";
            String str = null;
            if (userAgentString != null) {
                if (userAgentString.toUpperCase().contains("SAFARI")) {
                    str = "filename=\"" + new String(fileName.getBytes(StandardCharsets.UTF_8), "ISO8859-1") + "\"";
                } else {
                    str = "filename*=UTF-8''" + URLEncoder.encode(fileName, "UTF-8");
                }
            }
            if (str == null) {
                str = "filename=\"" + URLEncoder.encode(fileName, "UTF-8") + "\"";
            }
            builder.append(HttpHeaderNames.CONTENT_DISPOSITION).append(": attachment; ").append(str).append("\r\n");
        }

        builder.append("\r\n");
        builder.append(pem);
        log.debug("installRootCert response: {}", builder);
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(localOut));
        writer.write(builder.toString());
        writer.flush();
    }

    private void handleSSLSocket(InetSocketAddress remote, InputStream localIn, OutputStream localOut, Socket local, SSLSocket socket, String hostName) throws IOException, InterruptedException {
        log.debug("ssl proxy remote={}, socket={}, local={}, hostName={}, applicationLayerProtocols={}", remote, socket, local, hostName, applicationLayerProtocols);
        if (!applicationLayerProtocols.isEmpty()) {
            SSLSocket sslSocket = (SSLSocket) local;
            sslSocket.setHandshakeApplicationProtocolSelector((sslSocket1, clientProtocols) -> {
                log.debug("handshakeApplicationProtocolSelector sslSocket={}, clientProtocols={}, applicationProtocol={}", sslSocket1, clientProtocols, applicationProtocol);
                if (clientProtocols.contains(applicationProtocol)) {
                    return applicationProtocol;
                }
                for (String protocol : clientProtocols) {
                    if (applicationProtocol.startsWith(protocol)) {
                        return protocol;
                    }
                }
                return applicationProtocol;
            });
        }
        try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
            IPacketCapture packetCapture = vpn.getPacketCapture();
            Http2Filter filter = packetCapture == null ? null : packetCapture.getH2Filter();
            boolean filterHttp2 = filter != null && isHttp2(applicationProtocol) && allowFilterH2 && filter.filterHost(hostName);
            doForward(localIn, localOut, local, socketIn, socketOut, socket, vpn, hostName, filterHttp2, applicationLayerProtocols, applicationProtocol, true, packet);
        }
    }

    private static boolean isHttp2(String applicationProtocol) {
        return "h2".equals(applicationProtocol);
    }

    private static void doForward(InputStream localIn, OutputStream localOut, Socket local, InputStream socketIn, OutputStream socketOut, Socket socket, InspectorVpn vpn,
                                  String hostName, boolean filterHttp2, Collection<String> applicationProtocols, String applicationProtocol, boolean isSSL, Packet packet) throws InterruptedException {
        log.debug("doForward local={}, socket={}, hostName={}", local, socket, hostName);
        InetSocketAddress client = (InetSocketAddress) local.getRemoteSocketAddress();
        InetSocketAddress server = (InetSocketAddress) socket.getRemoteSocketAddress();
        IPacketCapture packetCapture = vpn == null ? null : vpn.getPacketCapture();
        if (packetCapture != null) {
            if (isSSL) {
                packetCapture.onSSLProxyEstablish(client, server, hostName, applicationProtocols, applicationProtocol);
            } else {
                packetCapture.onSocketEstablish(client, server);
            }
        }
        CountDownLatch countDownLatch = new CountDownLatch(2);
        StreamForward inbound, outbound;
        if (filterHttp2) {
            Http2Session session = new Http2Session(client.getAddress().getHostAddress(), server.getAddress().getHostAddress(), client.getPort(), server.getPort(), hostName);
            HttpFrameForward inboundForward = new HttpFrameForward(localIn, socketOut, true, client, server, countDownLatch, local, vpn, hostName,
                    session, packet);
            outbound = new HttpFrameForward(socketIn, localOut, false, client, server, countDownLatch, socket, vpn, hostName,
                    session, packet)
                    .setPeer(inboundForward);
            inbound = inboundForward;
        } else {
            inbound = new StreamForward(localIn, socketOut, true, client, server, countDownLatch, local, vpn, hostName, isSSL, packet);
            outbound = new StreamForward(socketIn, localOut, false, client, server, countDownLatch, socket, vpn, hostName, isSSL, packet);
        }
        inbound.startThread();
        outbound.startThread();
        countDownLatch.await();

        if (packetCapture != null) {
            if (isSSL) {
                packetCapture.onSSLProxyFinish(client, server, hostName);
            } else {
                packetCapture.onSocketFinish(client, server);
            }
        }
    }

    private void handleSocket(InetSocketAddress remote, InputStream localIn, OutputStream localOut, Socket local) throws Exception {
        DataInputStream dataInput = new DataInputStream(localIn);
        final ClientHelloRecord record = ExtensionServerName.parseServerNames(dataInput, remote);
        AllowRule allowRule = AllowRule.CONNECT_TCP;
        Proxy socketProxy = Proxy.NO_PROXY;
        String redirectAddress = null;
        int redirectPort = 0;
        String redirectHost = null;
        IPacketCapture packetCapture = vpn.getPacketCapture();
        if (packetCapture != null) {
            AcceptResult result = packetCapture.acceptTcp(record.newConnectRequest(packet));
            if (result != null) {
                allowRule = result.getRule();
                socketProxy = result.getSocketProxy();
                redirectAddress = result.getRedirectAddress();
                redirectPort = result.getRedirectPort();
                redirectHost = result.getRedirectHost();
            }
        }
        if (redirectAddress == null) {
            redirectAddress = remote.getAddress().getHostAddress();
        }
        if (redirectPort <= 0) {
            redirectPort = remote.getPort();
        }
        if (socketProxy == null) {
            socketProxy = Proxy.NO_PROXY;
        }
        log.debug("proxy remote={}, record={}, local={}, allowRule={}, socketProxy={}, redirect={}:{}", remote, record, local, allowRule, socketProxy, redirectAddress, redirectPort);
        if (allowRule == AllowRule.DISCONNECT) {
            throw new IOException(packet.daddr + ":" + packet.dport + " is not allowed connect: hostName=" + record.hostName);
        }
        if (record.hostName == null || allowRule == AllowRule.CONNECT_TCP) {
            try (Socket socket = new Socket(socketProxy)) {
                InetSocketAddress address;
                if (socketProxy != Proxy.NO_PROXY && socketProxy.type() == Proxy.Type.SOCKS && redirectHost != null) {
                    address = InetSocketAddress.createUnresolved(redirectHost, redirectPort);
                } else {
                    address = new InetSocketAddress(redirectAddress, redirectPort);
                }
                socket.connect(address, timeout);
                try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                    socketOut.write(record.prologue);
                    socketOut.flush();
                    doForward(localIn, localOut, local, socketIn, socketOut, socket, vpn, null, false, null, null, false, packet);
                }
            }
        } else {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            SecureRandom random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            context.init(new KeyManager[0], new TrustManager[]{DefaultTrustManager.INSTANCE}, random);
            SSLSocketFactory factory = context.getSocketFactory();
            Socket app = null;
            SSLSocket secureSocket = null;
            try {
                app = new Socket(socketProxy);
                app.connect(new InetSocketAddress(redirectAddress, redirectPort), timeout);
                secureSocket = (SSLSocket) factory.createSocket(app, record.hostName, redirectPort, true);
                if (!record.applicationLayerProtocols.isEmpty()) {
                    SSLParameters parameters = secureSocket.getSSLParameters();
                    parameters.setApplicationProtocols(record.applicationLayerProtocols.toArray(new String[0]));
                    secureSocket.setSSLParameters(parameters);
                }
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                secureSocket.addHandshakeCompletedListener(event -> {
                    try {
                        peerCertificate = (X509Certificate) event.getPeerCertificates()[0];
                        SSLSession session = event.getSession();
                        log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                    } catch (SSLPeerUnverifiedException e) {
                        log.debug("handshakeCompleted failed", e);
                    } finally {
                        countDownLatch.countDown();
                    }
                });
                secureSocket.startHandshake();
                countDownLatch.await();
                log.debug("secureSocket={}, applicationProtocol={}", secureSocket, secureSocket.getApplicationProtocol());
                if (peerCertificate == null) {
                    throw new IOException("Handshake failed with: " + record.hostName + ", remote=" + remote);
                }

                ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
                SSLContext serverContext = serverCertificate.createSSLContext(rootCert);
                SSLProxyV2 proxy = new SSLProxyV2(vpn, packet, timeout, serverContext, secureSocket,
                        record, secureSocket.getApplicationProtocol(), allowRule == AllowRule.FILTER_H2);
                try (Socket socket = SocketFactory.getDefault().createSocket("127.0.0.1", proxy.serverSocket.getLocalPort())) {
                    try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                        socketOut.write(record.prologue);
                        socketOut.flush();
                        doForward(localIn, localOut, local, socketIn, socketOut, socket, null, null, false, null, null, false, packet);
                    }
                }
            } catch (IOException e) {
                IoUtil.close(app);
                IoUtil.close(secureSocket);
                throw e;
            }
        }
    }

    private X509Certificate peerCertificate;

    private Allowed redirect() {
        return new Allowed("127.0.0.1", serverSocket.getLocalPort());
    }

}

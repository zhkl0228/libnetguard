package com.github.netguard.vpn.tcp;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.AcceptTcpResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.krakenapps.pcap.decoder.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxyV2 implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxyV2.class);

    private static final int SERVER_SO_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(1);

    public static Allowed create(final InspectorVpn vpn, final Packet packet, final int timeout) {
        try {
            log.debug("create tcp proxy packet={}", packet);
            SSLProxyV2 proxy = new SSLProxyV2(vpn, packet, timeout);
            Allowed allowed = proxy.redirect();
            log.debug("create tcp proxy packet={}, allowed={}", packet, allowed);
            return allowed;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void create(final InspectorVpn vpn, final Packet packet, final int timeout, Socket socket,
                              ConnectListener connectListener) {
        if (packet.saddr == null || packet.sport == 0) {
            InetSocketAddress remoteAddress = vpn.getRemoteSocketAddress();
            packet.saddr = remoteAddress.getAddress().getHostAddress();
            packet.sport = remoteAddress.getPort();
        }
        create(vpn, packet, timeout, socket, connectListener, null);
    }

    public static void create(final InspectorVpn vpn, final Packet packet, final int timeout, Socket socket,
                              ConnectListener connectListener, InputStream providedInputStream) {
        try {
            log.debug("create tcp proxy packet={}, socket={}", packet, socket);
            new SSLProxyV2(vpn, packet, timeout, socket, connectListener, providedInputStream);
            log.debug("create tcp proxy packet={}, socket={}", packet, socket);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private final InspectorVpn vpn;

    private final Packet packet;
    private final int timeout;
    private final ServerSocket serverSocket;
    private final SSLSocket secureSocket;
    private final Socket acceptedSocket;
    private final ConnectListener connectListener;
    private final InputStream providedInputStream;

    private SSLProxyV2(InspectorVpn vpn, Packet packet, int timeout, Socket socket, ConnectListener connectListener,
                       InputStream providedInputStream) throws IOException {
        this.vpn = vpn;

        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = null;
        this.hostName = null;
        this.applicationProtocol = null;
        this.allowFilterH2 = false;
        this.applicationLayerProtocols = Collections.emptyList();

        this.serverSocket = null;
        this.acceptedSocket = socket;
        this.connectListener = connectListener;
        this.providedInputStream = providedInputStream;
        this.forwardHandler = null;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        Thread thread = new Thread(this, "Proxy for " + packet + " at " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    private SSLProxyV2(InspectorVpn vpn, Packet packet, int timeout) throws IOException {
        this.vpn = vpn;

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
        this.connectListener = null;
        this.providedInputStream = null;
        this.forwardHandler = null;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        Thread thread = new Thread(this, "Proxy for " + packet + " at " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    private final String hostName;
    private final String applicationProtocol;
    private final boolean allowFilterH2;
    private final List<String> applicationLayerProtocols;
    private final ForwardHandler forwardHandler;

    private SSLProxyV2(InspectorVpn vpn, Packet packet, int timeout, SSLContext context, SSLSocket secureSocket,
                       ClientHelloRecord record, String applicationProtocol, boolean allowFilterH2, ForwardHandler forwardHandler) throws IOException {
        this.vpn = vpn;

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
        this.connectListener = null;
        this.providedInputStream = null;
        this.forwardHandler = forwardHandler;

        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        Thread thread = new Thread(this, "SSLProxy for " + packet + " at " + dateFormat.format(new Date()));
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        InetSocketAddress remote = packet.createServerAddress();
        try (Socket local = (serverSocket == null ? acceptedSocket : serverSocket.accept())) {
            try (InputStream localIn = providedInputStream == null ? local.getInputStream() : providedInputStream; OutputStream localOut = local.getOutputStream()) {
                if (packet.isInstallRootCert()) {
                    downloadRootCert(localIn, localOut);
                } else {
                    if (secureSocket != null) {
                        handleSSLSocket(localIn, localOut, local, secureSocket, hostName, forwardHandler);
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
        String pem = vpn.getRootCert().pem;
        StringBuilder builder = new StringBuilder();
        builder.append("HTTP/1.1 200 OK\r\n");
        builder.append(HttpHeaders.CONNECTION).append(": close\r\n");
        builder.append("Pragma").append(": no-cache\r\n");
        builder.append(HttpHeaders.CONTENT_TYPE).append(": application/x-pem-file\r\n");
        builder.append(HttpHeaders.CONTENT_LENGTH).append(": ").append(pem.length()).append("\r\n");
        builder.append(HttpHeaders.SERVER).append(": ").append(getClass().getSimpleName()).append("\r\n");

        {
            String fileName = "NetGuard.pem";
            String str = null;
            if (userAgentString != null) {
                if (userAgentString.toUpperCase().contains("SAFARI")) {
                    str = "filename=\"" + new String(fileName.getBytes(StandardCharsets.UTF_8), "ISO8859-1") + "\"";
                } else {
                    str = "filename*=UTF-8''" + URLEncoder.encode(fileName, StandardCharsets.UTF_8);
                }
            }
            if (str == null) {
                str = "filename=\"" + URLEncoder.encode(fileName, StandardCharsets.UTF_8) + "\"";
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

    private void handleSSLSocket(InputStream localIn, OutputStream localOut, Socket local, SSLSocket socket, String hostName,
                                 ForwardHandler forwardHandler) throws IOException, InterruptedException {
        log.debug("ssl proxy socket={}, local={}, hostName={}, applicationLayerProtocols={}", socket, local, hostName, applicationLayerProtocols);
        if (!applicationLayerProtocols.isEmpty()) {
            if (applicationProtocol != null) {
                SSLSocket sslSocket = (SSLSocket) local;
                sslSocket.setHandshakeApplicationProtocolSelector((ssl, clientProtocols) -> {
                    log.debug("handshakeApplicationProtocolSelector sslSocket={}, clientProtocols={}, applicationProtocol={}", ssl, clientProtocols, applicationProtocol);
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
        }
        try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
            IPacketCapture packetCapture = vpn.getPacketCapture();
            Http2Filter filter = packetCapture == null ? null : packetCapture.getH2Filter();
            boolean filterHttp2 = filter != null && isHttp2(applicationProtocol) && allowFilterH2 && filter.filterHost(hostName, false);
            doForward(localIn, localOut, local, socketIn, socketOut, socket, vpn, hostName, filterHttp2, applicationLayerProtocols, applicationProtocol, true, packet,
                    null, forwardHandler);
        }
    }

    private static boolean isHttp2(String applicationProtocol) {
        return Vpn.HTTP2_PROTOCOL.equals(applicationProtocol);
    }

    private static void doForward(InputStream localIn, OutputStream localOut, Socket local, InputStream socketIn, OutputStream socketOut, Socket socket, InspectorVpn vpn,
                                  String hostName, boolean filterHttp2, Collection<String> applicationProtocols, String applicationProtocol, boolean isSSL, Packet packet,
                                  byte[] prologue, ForwardHandler forwardHandler) throws InterruptedException, IOException {
        log.debug("doForward local={}, socket={}, hostName={}", local, socket, hostName);
        InetSocketAddress client = (InetSocketAddress) local.getRemoteSocketAddress();
        InetSocketAddress server = (InetSocketAddress) socket.getRemoteSocketAddress();
        if (hostName != null && !hostName.isBlank()) {
            server = new InetSocketAddress(hostName, server.getPort());
        }
        IPacketCapture packetCapture = vpn == null ? null : vpn.getPacketCapture();
        if (packetCapture != null) {
            if (isSSL) {
                String application = null;
                Application[] applications = vpn.queryApplications(packet.hashCode());
                if (applications != null) {
                    List<String> list = new ArrayList<>(applications.length);
                    for (Application app : applications) {
                        list.add(app.getPackageName());
                    }
                    application = String.join(",", list);
                }
                packetCapture.onSSLProxyEstablish(client, server, hostName, applicationProtocols, applicationProtocol, application);
            } else {
                packetCapture.onSocketEstablish(client, server);
            }
        }
        CountDownLatch countDownLatch = new CountDownLatch(2);
        StreamForward inbound, outbound;
        if (filterHttp2) {
            Http2Session session = new Http2Session(client.getAddress().getHostAddress(), server.getAddress().getHostAddress(), client.getPort(), server.getPort(), hostName);
            HttpFrameForward inboundForward = new HttpFrameForward(localIn, socketOut, true, client, server, countDownLatch, local, vpn, hostName,
                    session, packet, forwardHandler);
            outbound = new HttpFrameForward(socketIn, localOut, false, client, server, countDownLatch, socket, vpn, hostName,
                    session, packet, forwardHandler)
                    .setPeer(inboundForward);
            inbound = inboundForward;
        } else {
            inbound = new StreamForward(localIn, socketOut, true, client, server, countDownLatch, local, vpn, hostName, isSSL, packet, forwardHandler);
            outbound = new StreamForward(socketIn, localOut, false, client, server, countDownLatch, socket, vpn, hostName, isSSL, packet, forwardHandler);
        }
        inbound.startThread(prologue);
        outbound.startThread(null);
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
        ClientHelloRecord record = ExtensionServerName.parseServerNames(dataInput, remote);
        AllowRule allowRule = AllowRule.CONNECT_TCP;
        Proxy socketProxy = Proxy.NO_PROXY;
        String redirectAddress = null;
        int redirectPort = 0;
        String redirectHost = null;
        IPacketCapture packetCapture = vpn.getPacketCapture();
        AcceptTcpResult result = null;
        if (packetCapture != null) {
            try {
                while (true) {
                    result = packetCapture.acceptTcp(record.newConnectRequest(vpn, packet));
                    if (result == null) {
                        break;
                    }
                    if (result.getRule() == AllowRule.__CUSTOM_HANDLE) {
                        PushbackInputStream pushbackInputStream = new PushbackInputStream(localIn, record.prologue.length);
                        pushbackInputStream.unread(record.prologue);
                        result.customHandler.handle(pushbackInputStream, localOut);
                        return;
                    }
                    if (result.getRule() == AllowRule.__READ_MORE_PROLOGUE) {
                        int soTimeout = local.getSoTimeout();
                        try {
                            local.setSoTimeout(800);
                            record = record.readMorePrologue(dataInput, result.needPrologueCount);
                        } catch (SocketTimeoutException e) {
                            log.debug("readMorePrologue", e);
                        } finally {
                            local.setSoTimeout(soTimeout);
                        }
                    } else {
                        break;
                    }
                }
            } catch (Exception e) {
                log.warn("acceptTcp failed", e);
            }
            if (result != null) {
                allowRule = result.getRule();
                socketProxy = result.getSocketProxy();
                redirectAddress = result.getRedirectAddress();
                redirectPort = result.getRedirectPort();
                redirectHost = result.getRedirectHost();
            }
        }
        if (redirectAddress == null) {
            redirectAddress = remote.getHostString();
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
        if (record.isSSL() && allowRule != AllowRule.CONNECT_TCP) {
            SSLContext context = AcceptTcpResult.newSSLContext(result);
            SSLSocketFactory factory = context.getSocketFactory();
            Socket app = null;
            SSLSocket secureSocket = null;
            try {
                app = new Socket(socketProxy);
                InetSocketAddress address = createSocketAddress(socketProxy, redirectAddress, redirectPort, redirectHost);
                app.connect(address, timeout);
                secureSocket = (SSLSocket) factory.createSocket(app, record.hostName == null ? remote.getAddress().getHostAddress() : record.hostName, redirectPort, true);
                if (!record.applicationLayerProtocols.isEmpty()) {
                    setApplicationProtocols(secureSocket, record.applicationLayerProtocols.toArray(new String[0]));
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
                if (connectListener != null) {
                    connectListener.onConnected(secureSocket);
                }
                String applicationProtocol = null;
                try {
                    applicationProtocol = secureSocket.getApplicationProtocol();
                } catch(UnsupportedOperationException e) {
                    log.warn("secureSocket={}", secureSocket, e);
                }
                log.debug("secureSocket={}, applicationProtocol={}", secureSocket, applicationProtocol);
                if (peerCertificate == null) {
                    throw new IOException("Handshake failed with: " + record.hostName + ", remote=" + remote);
                }

                ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
                SSLContext serverContext = serverCertificate.getServerContext(vpn.getRootCert()).newSSLContext();
                SSLProxyV2 proxy = new SSLProxyV2(vpn, packet, timeout, serverContext, secureSocket,
                        record, applicationProtocol, allowRule == AllowRule.FILTER_H2, result.forwardHandler);
                try (Socket socket = SocketFactory.getDefault().createSocket("127.0.0.1", proxy.serverSocket.getLocalPort())) {
                    try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                        if (record.prologue.length > 0) {
                            socketOut.write(record.prologue);
                            socketOut.flush();
                        }
                        doForward(localIn, localOut, local, socketIn, socketOut, socket, null, record.hostName, false, null, null, false, packet,
                                record.prologue, null);
                    }
                }
            } catch (IOException e) {
                if (e instanceof SocketException && e.getMessage().contains("SOCKS")) {
                    log.info("SSL proxy for {} failed", socketProxy, e);
                }
                IoUtil.close(app);
                IoUtil.close(secureSocket);
                throw e;
            }
        } else {
            try (Socket socket = new Socket(socketProxy)) {
                InetSocketAddress address = createSocketAddress(socketProxy, redirectAddress, redirectPort, redirectHost);
                socket.connect(address, timeout);
                if (connectListener != null) {
                    connectListener.onConnected(socket);
                }
                try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                    ForwardHandler forwardHandler = result == null ? null : result.forwardHandler;
                    if (forwardHandler == null) {
                        if (record.prologue.length > 0) {
                            socketOut.write(record.prologue);
                            socketOut.flush();
                        }
                    }
                    doForward(localIn, localOut, local, socketIn, socketOut, socket, vpn, record.hostName, false, null, null, false, packet,
                            record.prologue, forwardHandler);
                }
            }
        }
    }

    private InetSocketAddress createSocketAddress(Proxy socketProxy, String redirectAddress, int redirectPort, String redirectHost) {
        InetSocketAddress address;
        if (socketProxy != Proxy.NO_PROXY && socketProxy.type() == Proxy.Type.SOCKS && redirectHost != null) {
            address = InetSocketAddress.createUnresolved(redirectHost, redirectPort);
        } else {
            address = new InetSocketAddress(redirectAddress, redirectPort);
        }
        return address;
    }

    private static Method isConscrypt, setApplicationProtocols;
    static {
        try {
            Class<?> cConscrypt = Class.forName("org.conscrypt.Conscrypt");
            isConscrypt = cConscrypt.getMethod("isConscrypt", SSLSocket.class);
            setApplicationProtocols = cConscrypt.getMethod("setApplicationProtocols", SSLSocket.class, String[].class);
        } catch(Exception ignored) {}
    }

    private void setApplicationProtocols(SSLSocket secureSocket, String[] applicationLayerProtocols) {
        SSLParameters parameters = secureSocket.getSSLParameters();
        parameters.setApplicationProtocols(applicationLayerProtocols);
        secureSocket.setSSLParameters(parameters);

        if(isConscrypt != null && setApplicationProtocols != null) {
            try {
                boolean ret = (Boolean) isConscrypt.invoke(null, secureSocket);
                if (ret) {
                    setApplicationProtocols.invoke(null, secureSocket, applicationLayerProtocols);
                }
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new IllegalStateException("setApplicationProtocols", e);
            }
        }
    }

    private X509Certificate peerCertificate;

    private Allowed redirect() {
        return new Allowed("127.0.0.1", serverSocket.getLocalPort());
    }

}

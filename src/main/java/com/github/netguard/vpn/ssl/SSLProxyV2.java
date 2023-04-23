package com.github.netguard.vpn.ssl;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.ssl.h2.Http2Session;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SSLProxyV2 implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLProxyV2.class);

    private static final int SERVER_SO_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(1);

    public static Allowed create(final InspectorVpn vpn, RootCert rootCert, final Packet packet, final int timeout) {
        try {
            log.debug("create tcp proxy packet={}", packet);
            IPacketCapture packetCapture = vpn.getPacketCapture();
            SSLProxyV2 proxy = new SSLProxyV2(rootCert, packetCapture, packet, timeout);
            Allowed allowed = proxy.redirect();
            log.debug("create tcp proxy packet={}, allowed={}", packet, allowed);
            return allowed;
        } catch (IOException e) {
            log.warn("create SSLProxy failed", e);
            return null;
        }
    }

    private final RootCert rootCert;

    private final Packet packet;
    private final IPacketCapture packetCapture;
    private final int timeout;
    private final ServerSocket serverSocket;
    private final SSLSocket secureSocket;

    private SSLProxyV2(RootCert rootCert, IPacketCapture packetCapture, Packet packet, int timeout) throws IOException {
        this.rootCert = rootCert;

        this.packetCapture = packetCapture;
        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = null;
        this.hostName = null;
        this.applicationProtocol = null;

        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLoopbackAddress());
        this.serverSocket.setSoTimeout(SERVER_SO_TIMEOUT);

        Thread thread = new Thread(this, "Proxy for " + packet);
        thread.setDaemon(true);
        thread.start();
    }

    private final String hostName;
    private final String applicationProtocol;

    private SSLProxyV2(IPacketCapture packetCapture, Packet packet, int timeout, SSLContext context, SSLSocket secureSocket, String hostName, String applicationProtocol) throws IOException {
        this.rootCert = null;

        this.packetCapture = packetCapture;
        this.packet = packet;
        this.timeout = timeout;
        this.secureSocket = secureSocket;
        this.hostName = hostName;
        this.applicationProtocol = applicationProtocol;

        SSLServerSocketFactory factory = context.getServerSocketFactory();
        this.serverSocket = factory.createServerSocket(0, 0, InetAddress.getLoopbackAddress());
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
        log.debug("ssl proxy remote={}, socket={}, local={}, hostName={}, applicationProtocol={}", remote, socket, local, hostName, applicationProtocol);
        if (applicationProtocol != null && !applicationProtocol.isEmpty()) {
            SSLSocket sslSocket = (SSLSocket) local;
            SSLParameters parameters = sslSocket.getSSLParameters();
            parameters.setApplicationProtocols(new String[]{applicationProtocol});
            sslSocket.setSSLParameters(parameters);
        }
        try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
            Http2Filter filter = packetCapture == null ? null : packetCapture.getH2Filter();
            boolean filterHttp2 = filter != null && isHttp2(applicationProtocol) && filter.acceptHost(hostName);
            doForward(localIn, localOut, local, socketIn, socketOut, socket, packetCapture, hostName, filterHttp2, applicationProtocol);
        }
    }

    private static boolean isHttp2(String applicationProtocol) {
        return "h2".equals(applicationProtocol);
    }

    private static void doForward(InputStream localIn, OutputStream localOut, Socket local, InputStream socketIn, OutputStream socketOut, Socket socket, IPacketCapture packetCapture,
                                  String hostName, boolean filterHttp2, String applicationProtocol) throws InterruptedException {
        log.debug("doForward local={}, socket={}, hostName={}", local, socket, hostName);
        InetSocketAddress client = (InetSocketAddress) local.getRemoteSocketAddress();
        InetSocketAddress server = (InetSocketAddress) socket.getRemoteSocketAddress();
        if (packetCapture != null) {
            packetCapture.onSSLProxyEstablish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), hostName, applicationProtocol);
        }
        CountDownLatch countDownLatch = new CountDownLatch(2);
        StreamForward inbound, outbound;
        if (filterHttp2) {
            Http2Session session = new Http2Session(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), hostName);
            HttpFrameForward inboundForward = new HttpFrameForward(localIn, socketOut, true, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, local, packetCapture, hostName,
                    session);
            outbound = new HttpFrameForward(socketIn, localOut, false, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, socket, packetCapture, hostName,
                    session)
                    .setPeer(inboundForward);
            inbound = inboundForward;
        } else {
            inbound = new StreamForward(localIn, socketOut, true, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, local, packetCapture, hostName);
            outbound = new StreamForward(socketIn, localOut, false, client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), countDownLatch, socket, packetCapture, hostName);
        }
        inbound.startThread();
        outbound.startThread();
        countDownLatch.await();

        if (packetCapture != null) {
            packetCapture.onSSLProxyFinish(client.getHostString(), server.getHostString(), client.getPort(), server.getPort(), hostName);
        }
    }

    private void handleSocket(InetSocketAddress remote, InputStream localIn, OutputStream localOut, Socket local) throws Exception {
        DataInput dataInput = new DataInputStream(localIn);
        final ClientHelloRecord record = ExtensionServerName.parseServerNames(dataInput, remote);
        log.debug("proxy remote={}, record={}, local={}", remote, record, local);
        if (record.hostName == null) {
            if (packetCapture != null) {
                if (!packetCapture.acceptTcp(packet.daddr, packet.dport)) {
                    throw new IOException(packet.daddr + ":" + packet.dport + " is not allowed connect.");
                }
            }
            try (Socket socket = new Socket()) {
                socket.connect(remote, timeout);
                try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                    socketOut.write(record.readData);
                    socketOut.flush();
                    doForward(localIn, localOut, local, socketIn, socketOut, socket, null, null, false, null);
                }
            }
        } else {
            if (packetCapture != null) {
                if (!packetCapture.acceptSSL(record.hostName, packet.daddr, packet.dport, record.applicationLayerProtocols)) {
                    throw new IOException(record.hostName + " is not allowed connect.");
                }
            }
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            Socket app = null;
            SSLSocket secureSocket = null;
            try {
                app = new Socket();
                app.connect(remote, timeout);
                secureSocket = (SSLSocket) factory.createSocket(app, record.hostName, remote.getPort(), true);
                if (!record.applicationLayerProtocols.isEmpty()) {
                    SSLParameters parameters = secureSocket.getSSLParameters();
                    parameters.setApplicationProtocols(record.applicationLayerProtocols.toArray(new String[0]));
                    secureSocket.setSSLParameters(parameters);
                }
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
                log.debug("secureSocket={}, applicationProtocol={}", secureSocket, secureSocket.getApplicationProtocol());
                if (peerCertificate == null) {
                    throw new IOException("Handshake failed with: " + record.hostName + ", remote=" + remote);
                }

                ServerCertificate serverCertificate = new ServerCertificate(peerCertificate);
                SSLContext serverContext = serverCertificate.createSSLContext(rootCert);
                SSLProxyV2 proxy = new SSLProxyV2(packetCapture, packet, timeout, serverContext, secureSocket, record.hostName, secureSocket.getApplicationProtocol());
                try (Socket socket = SocketFactory.getDefault().createSocket("127.0.0.1", proxy.serverSocket.getLocalPort())) {
                    try (InputStream socketIn = socket.getInputStream(); OutputStream socketOut = socket.getOutputStream()) {
                        socketOut.write(record.readData);
                        socketOut.flush();
                        doForward(localIn, localOut, local, socketIn, socketOut, socket, null, null, false, null);
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

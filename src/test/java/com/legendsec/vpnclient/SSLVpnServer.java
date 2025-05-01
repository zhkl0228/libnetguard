package com.legendsec.vpnclient;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.net.DefaultTrustManager;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.StreamForward;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

class SSLVpnServer implements Runnable {

    static {
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    private static final Logger log = LoggerFactory.getLogger(SSLVpnServer.class);

    private final InetSocketAddress server;
    private final ServerSocket serverSocket;
    private final SSLSocketFactory factory;

    private final List<String> applicationProtocols;
    private String applicationProtocol;

    SSLVpnServer(String hostName, int serverPort, int port, List<String> applicationProtocols) throws IOException {
        this.server = new InetSocketAddress(hostName, serverPort);
        this.applicationProtocols = applicationProtocols;
        try {
            ServerCertificate serverCertificate = new ServerCertificate(null);
            SSLContext serverContext = serverCertificate.getServerContext(RootCert.load(), getClass().getSimpleName()).newSSLContext("TLS", null);
            this.factory = serverContext.getSocketFactory();
            this.serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("connect vpn ssl socket", e);
        }

        this.serverSocket.setReuseAddress(true);
        Thread thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }

    final int getListenPort() {
        return serverSocket.getLocalPort();
    }

    @Override
    public void run() {
        try {
            while (true) {
                try {
                    String lanIP = Inspector.detectLanIP();
                    final Socket socket = this.serverSocket.accept();
                    Thread thread = new Thread(() -> {
                        try {
                            final InputStream inputStream;
                            final OutputStream outputStream;
                            PushbackInputStream pushbackInputStream = new PushbackInputStream(socket.getInputStream());
                            int magic = pushbackInputStream.read();
                            if (magic == -1) {
                                throw new EOFException();
                            }
                            log.debug("Accepted connection from {}, lanIP={}, magic=0x{}", socket.getRemoteSocketAddress(), lanIP, Integer.toHexString(magic));
                            pushbackInputStream.unread(magic);
                            boolean ssl = magic == 0x16;
                            if (ssl) {
                                SSLSocket sslSocket = (SSLSocket) factory.createSocket(socket, pushbackInputStream, true);
                                sslSocket.setUseClientMode(false);
                                log.debug("enabledCipherSuites={}", (Object) sslSocket.getEnabledCipherSuites());

                                final CountDownLatch countDownLatch = new CountDownLatch(1);
                                sslSocket.addHandshakeCompletedListener(event -> {
                                    try {
                                        SSLSession session = event.getSession();
                                        log.debug("handshakeCompleted peerHost={}", session.getPeerHost());
                                    } finally {
                                        countDownLatch.countDown();
                                    }
                                });
                                sslSocket.startHandshake();
                                if (!countDownLatch.await(30, TimeUnit.SECONDS)) {
                                    throw new IOException("Handshake timed out");
                                }
                                inputStream = sslSocket.getInputStream();
                                outputStream = sslSocket.getOutputStream();
                            } else {
                                inputStream = pushbackInputStream;
                                outputStream = socket.getOutputStream();
                            }
                            handleSocket(socket, inputStream, outputStream, ssl);
                        } catch (Exception e) {
                            log.warn("handle socket", e);
                        }
                    });
                    thread.start();
                } catch (SocketTimeoutException e) {
                    break;
                }
            }
        } catch (Exception e) {
            log.debug("handle server socket", e);
        } finally {
            IoUtil.close(serverSocket);
        }
    }

    private void handleSocket(Socket socket, InputStream inputStream, OutputStream outputStream, boolean ssl) throws Exception {
        final InetSocketAddress client = (InetSocketAddress) socket.getRemoteSocketAddress();
        final Socket clientSocket;
        if (ssl) {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(new KeyManager[0], new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
            SSLSocketFactory factory = context.getSocketFactory();

            Socket app = new Socket();
            app.connect(server, 10000);
            SSLSocket secureSocket = (SSLSocket) factory.createSocket(app, server.getHostName(), server.getPort(), true);
            clientSocket = secureSocket;
            if (!applicationProtocols.isEmpty()) {
                SSLParameters parameters = secureSocket.getSSLParameters();
                parameters.setApplicationProtocols(applicationProtocols.toArray(new String[0]));
                secureSocket.setSSLParameters(parameters);
            }
            try {
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                secureSocket.addHandshakeCompletedListener(event -> {
                    try {
                        SSLSession session = event.getSession();
                        log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                    } finally {
                        countDownLatch.countDown();
                    }
                });
                secureSocket.startHandshake();
                countDownLatch.await();

                applicationProtocol = secureSocket.getApplicationProtocol();
            } catch(UnsupportedOperationException e) {
                log.warn("socket={}", socket, e);
            }
            log.debug("secureSocket={}, applicationProtocol={}", secureSocket, applicationProtocol);

            if (applicationProtocol != null && !applicationProtocol.isEmpty()) {
                ((SSLSocket) socket).setHandshakeApplicationProtocolSelector((_s, clientProtocols) -> {
                    log.debug("handshakeApplicationProtocolSelector sslSocket={}, clientProtocols={}, applicationProtocol={}", _s, clientProtocols, applicationProtocol);
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
        } else {
            clientSocket = new Socket();
            clientSocket.connect(server, 10000);
        }

        try (InputStream localIn = inputStream; OutputStream localOut = outputStream;
             InputStream socketIn = clientSocket.getInputStream(); OutputStream socketOut = clientSocket.getOutputStream()) {
            CountDownLatch countDownLatch = new CountDownLatch(2);
            SacMsgStreamForward inbound, outbound;
            inbound = new SacMsgStreamForward(localIn, socketOut, true, client, server, countDownLatch, socket, server.getHostName());
            outbound = new SacMsgStreamForward(socketIn, localOut, false, client, server, countDownLatch, clientSocket, server.getHostName());
            inbound.startThread();
            outbound.startThread();
            countDownLatch.await();
        }
    }

    private static class SacMsgStreamForward extends StreamForward {
        public SacMsgStreamForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket,
                                   String hostName) {
            super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, null, hostName, true, null);
        }
        public void startThread() {
            startThread(null);
        }
        @Override
        protected void notifyForward(byte[] buf, int read) {
            byte[] data = Arrays.copyOf(buf, read);
            log.debug("{}", Inspector.inspectString(data, String.format("notifyForward server=%s, base64=%s", server, Base64.encode(data))));
            super.notifyForward(buf, read);
        }
    }

    final void close() {
        IoUtil.close(serverSocket);
    }
}

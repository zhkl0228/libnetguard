package com.legendsec.vpnclient;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.net.DefaultTrustManager;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.StreamForward;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

class SSLVpnServer implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SSLVpnServer.class);

    private final InetSocketAddress server;
    private final ServerSocket serverSocket;

    private final List<String> applicationProtocols;
    private String applicationProtocol;

    SSLVpnServer(String hostName, int serverPort, int port, List<String> applicationProtocols) throws IOException {
        this.server = new InetSocketAddress(hostName, serverPort);
        this.applicationProtocols = applicationProtocols;
        try {
            ServerCertificate serverCertificate = new ServerCertificate(null);
            SSLContext serverContext = serverCertificate.getServerContext(RootCert.load()).newSSLContext();
            this.serverSocket = serverContext.getServerSocketFactory().createServerSocket(port, 0);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("connect vpn ssl socket", e);
        }

        this.serverSocket.setReuseAddress(true);
        this.serverSocket.setSoTimeout(60000);
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
                    final SSLSocket socket = (SSLSocket) this.serverSocket.accept();
                    log.debug("Accepted connection from {}, lanIP={}", socket.getRemoteSocketAddress(), lanIP);
                    Thread thread = new Thread(() -> {
                        try {
                            handleSocket(socket);
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

    private void handleSocket(SSLSocket socket) throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(new KeyManager[0], new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        Socket app = new Socket();
        app.connect(server, 10000);
        SSLSocket clientSocket = (SSLSocket) factory.createSocket(app, server.getHostName(), server.getPort(), true);
        if (!applicationProtocols.isEmpty()) {
            SSLParameters parameters = clientSocket.getSSLParameters();
            parameters.setApplicationProtocols(applicationProtocols.toArray(new String[0]));
            clientSocket.setSSLParameters(parameters);
        }
        try {
            final CountDownLatch countDownLatch = new CountDownLatch(1);
            clientSocket.addHandshakeCompletedListener(event -> {
                try {
                    SSLSession session = event.getSession();
                    log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                } finally {
                    countDownLatch.countDown();
                }
            });
            clientSocket.startHandshake();
            countDownLatch.await();

            applicationProtocol = clientSocket.getApplicationProtocol();
        } catch(UnsupportedOperationException e) {
            log.warn("secureSocket={}", clientSocket, e);
        }
        log.debug("secureSocket={}, applicationProtocol={}", clientSocket, applicationProtocol);

        InetSocketAddress client = (InetSocketAddress) socket.getRemoteSocketAddress();
        if (applicationProtocol != null && !applicationProtocol.isEmpty()) {
            socket.setHandshakeApplicationProtocolSelector((ssl, clientProtocols) -> {
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

        try (InputStream localIn = socket.getInputStream(); OutputStream localOut = socket.getOutputStream();
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
        private boolean isSSL;
        @Override
        protected boolean forward(byte[] buf) throws IOException {
            if (isSSL) {
                return super.forward(buf);
            }
            final DataInput dataInput = new DataInputStream(inputStream);
            int tag = dataInput.readInt();
            if (server) {
                switch (tag) {
                    case GatewayAgent.VPN_GET_PORTAL:
                    case GatewayAgent.VPN_LOGIN:
                    case GatewayAgent.VPN_GET_USERDATA:
                    case GatewayAgent.VPN_HEARTBEAT:
                    case GatewayAgent.VPN_LOGOUT:
                    case GatewayAgent.VPN_SMS_SEND:
                    case GatewayAgent.VPN_SUB_AUTH:
                    case GatewayAgent.VPN_QUERY_APP_LIST:
                    {
                        final int length = dataInput.readInt();
                        byte[] msg = new byte[length];
                        dataInput.readFully(msg);
                        if (log.isDebugEnabled()) {
                            byte[] tmp = msg;
                            if (tmp.length > 32) {
                                tmp = Arrays.copyOf(tmp, 32);
                            }
                            log.debug("{}", Inspector.inspectString(tmp, String.format("forward %d bytes server", msg.length)));
                        }

                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        int jsonSize = buffer.getInt();
                        if (jsonSize <= buffer.remaining()) {
                            byte[] json = new byte[jsonSize];
                            buffer.get(json);
                            JSONObject obj = JSON.parseObject(new String(json, StandardCharsets.UTF_8).trim(), Feature.OrderedField);
                            log.info("handleMsgReq: tag=0x{}, {}", Integer.toHexString(tag), obj == null ? "json=" + HexUtil.encodeHexStr(json) : obj.toString(SerializerFeature.PrettyFormat));
                        } else {
                            log.warn("Received wrong buffer length: {}, remaining={}", jsonSize, buffer.remaining());
                        }
                        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 8)) {
                            DataOutput dataOutput = new DataOutputStream(baos);
                            dataOutput.writeInt(tag);
                            dataOutput.writeInt(msg.length);
                            dataOutput.write(msg);
                            outputStream.write(baos.toByteArray());
                            outputStream.flush();
                        }
                        break;
                    }
                    case 0x47455420: {
                        log.debug("Received SSL tag: 0x{}, socket={}", Integer.toHexString(tag), socket);
                        isSSL = true;
                        new DataOutputStream(outputStream).writeInt(tag);
                        return super.forward(buf);
                    }
                    default: {
                        log.warn("Received unknown req tag: 0x{}, socket={}", Integer.toHexString(tag), socket);
                        isSSL = true;
                        new DataOutputStream(outputStream).writeInt(tag);
                        return super.forward(buf);
                    }
                }
            } else {
                switch (tag & Integer.MAX_VALUE) {
                    case GatewayAgent.VPN_GET_PORTAL:
                    case GatewayAgent.VPN_LOGIN:
                    case GatewayAgent.VPN_GET_USERDATA:
                    case GatewayAgent.VPN_HEARTBEAT:
                    case GatewayAgent.VPN_LOGOUT:
                    case GatewayAgent.VPN_SMS_SEND:
                    case GatewayAgent.VPN_SUB_AUTH:
                    case GatewayAgent.VPN_QUERY_APP_LIST:
                    {
                        final int length = dataInput.readInt();
                        final int error = dataInput.readInt();
                        byte[] msg = new byte[length - 4];
                        dataInput.readFully(msg);
                        if (log.isDebugEnabled()) {
                            byte[] tmp = msg;
                            if (tmp.length > 32) {
                                tmp = Arrays.copyOf(tmp, 32);
                            }
                            log.debug("{}", Inspector.inspectString(tmp, String.format("forward %d bytes client error=0x%s", msg.length, Integer.toHexString(error))));
                        }

                        if (error == 0) {
                            ByteBuffer buffer = ByteBuffer.wrap(msg);
                            if (buffer.remaining() >= 4 && buffer.getInt() > 0) {
                                byte[] json = new byte[buffer.remaining()];
                                buffer.get(json);
                                JSONObject obj = JSON.parseObject(new String(json, StandardCharsets.UTF_8).trim(), Feature.OrderedField);
                                log.info("handleMsgResp: tag=0x{}, {}", Integer.toHexString(tag), obj == null ? "json=" + HexUtil.encodeHexStr(json) : obj.toString(SerializerFeature.PrettyFormat));
                            } else {
                                log.info("handleMsgResp: tag=0x{}", Integer.toHexString(tag));
                            }
                        }
                        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 12)) {
                            DataOutput dataOutput = new DataOutputStream(baos);
                            dataOutput.writeInt(tag);
                            dataOutput.writeInt(msg.length + 4);
                            dataOutput.writeInt(error);
                            dataOutput.write(msg);
                            outputStream.write(baos.toByteArray());
                            outputStream.flush();
                            break;
                        }
                    }
                    case 0x48545450: { // SSL
                        log.debug("Received HTTP tag: 0x{}, socket={}", Integer.toHexString(tag), socket);
                        isSSL = true;
                        new DataOutputStream(outputStream).writeInt(tag);
                        return super.forward(buf);
                    }
                    default: {
                        log.warn("Received unknown resp tag: 0x{}, socket={}", Integer.toHexString(tag), socket);
                        isSSL = true;
                        new DataOutputStream(outputStream).writeInt(tag);
                        return super.forward(buf);
                    }
                }
            }
            return false;
        }
    }
}

package com.legendsec.vpnclient;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.net.DefaultTrustManager;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.Inspector;
import com.github.netguard.handler.PcapFileOutputStream;
import com.github.netguard.sslvpn.qianxin.GatewayAgent;
import com.github.netguard.sslvpn.qianxin.QianxinVPN;
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
import java.util.ArrayList;
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
            SSLContext serverContext = serverCertificate.getServerContext(RootCert.load(), getClass().getSimpleName()).newSSLContext();
            this.serverSocket = serverContext.getServerSocketFactory().createServerSocket(port, 0);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("connect vpn ssl socket", e);
        }

        this.serverSocket.setReuseAddress(true);
//        this.serverSocket.setSoTimeout(60000);
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
             InputStream socketIn = clientSocket.getInputStream(); OutputStream socketOut = clientSocket.getOutputStream();
             PcapFileOutputStream pcap = new PcapFileOutputStream(new File(String.format("target/ssl_vpn_%d.pcap", System.currentTimeMillis())))) {
            CountDownLatch countDownLatch = new CountDownLatch(2);
            SacMsgStreamForward inbound, outbound;
            inbound = new SacMsgStreamForward(localIn, socketOut, true, client, server, countDownLatch, socket, server.getHostName(), pcap);
            outbound = new SacMsgStreamForward(socketIn, localOut, false, client, server, countDownLatch, clientSocket, server.getHostName(), pcap);
            inbound.startThread();
            outbound.startThread();
            countDownLatch.await();
        }
    }

    private static class SacMsgStreamForward extends StreamForward {
        private final PcapFileOutputStream pcap;
        public SacMsgStreamForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket,
                                   String hostName, PcapFileOutputStream pcap) {
            super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, null, hostName, true, null);
            this.pcap = pcap;
        }
        public void startThread() {
            startThread(null);
        }
        private static String readStr(ByteBuffer buffer) {
            int length = buffer.getInt();
            byte[] bytes = new byte[length];
            buffer.get(bytes);
            int off = length % 4;
            if (off > 0) {
                buffer.position(buffer.position() - off + 4);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
        private boolean isSSL;
        @Override
        protected boolean forward(byte[] buf) throws IOException {
            if (isSSL) {
                log.debug("forward server={} SSL stream: socket={}", server, socket);
                return super.forward(buf);
            }
            final DataInput dataInput = new DataInputStream(inputStream);
            int tag = dataInput.readInt();
            if (server) {
                switch (tag) {
                    case GatewayAgent.VPN_PROXY_ACCESS: {
                        final int length = dataInput.readInt();
                        byte[] msg = new byte[length];
                        dataInput.readFully(msg);
                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        byte[] ticket = new byte[32];
                        buffer.get(ticket);
                        String username = readStr(buffer);
                        int version = buffer.getInt();
                        int extFlag = buffer.getInt();
                        int svcId = buffer.getInt();
                        String svr_name = readStr(buffer);
                        String svr_ip = readStr(buffer);
                        String svr_port = readStr(buffer);
                        int compress = buffer.getInt();
                        int count = buffer.getInt();
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes proxy server: username=%s, version=%d, extFlag=0x%x, svcId=%d, svr_name=%s, svr_ip=%s, svr_port=%s, compress=%d, count=%d, remaining=%d, socket=%s", msg.length, username,
                                    version, extFlag, svcId, svr_name, svr_ip, svr_port, compress, count, buffer.remaining(), socket)));
                        }
                        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 8)) {
                            DataOutput dataOutput = new DataOutputStream(baos);
                            dataOutput.writeInt(tag);
                            dataOutput.writeInt(length);
                            dataOutput.write(msg);
                            outputStream.write(baos.toByteArray());
                            outputStream.flush();
                        }
                        break;
                    }
                    case GatewayAgent.VPN_NC_ACCESS: {
                        final int length = dataInput.readInt();
                        byte[] msg = new byte[length];
                        dataInput.readFully(msg);
                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        byte[] ticket = new byte[32];
                        buffer.get(ticket);
                        String username = readStr(buffer);
                        String password = null;
                        int version = buffer.getInt();
                        int compress = buffer.getInt();
                        String ip = null;
                        if (version > 0) {
                            ip = readStr(buffer);
                        }
                        if (version > 1) {
                            password = readStr(buffer);
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes NC server: username=%s, password=%s, version=%d, compress=%s, ip=%s, socket=%s", msg.length, username, password, version, compress, ip, socket)));
                        }
                        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 8)) {
                            DataOutput dataOutput = new DataOutputStream(baos);
                            dataOutput.writeInt(tag);
                            dataOutput.writeInt(length);
                            dataOutput.write(msg);
                            outputStream.write(baos.toByteArray());
                            outputStream.flush();
                        }
                        break;
                    }
                    case GatewayAgent.VPN_PRD_DATA: {
                        final int length = dataInput.readInt();
                        byte[] msg = new byte[length];
                        dataInput.readFully(msg);
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes prd data server, socket=%s", msg.length, socket)));
                        }
                        pcap.writePacket(Arrays.copyOfRange(msg, 4, msg.length));
                        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 8)) {
                            DataOutput dataOutput = new DataOutputStream(baos);
                            dataOutput.writeInt(tag);
                            dataOutput.writeInt(length);
                            dataOutput.write(msg);
                            outputStream.write(baos.toByteArray());
                            outputStream.flush();
                        }
                        break;
                    }
                    case GatewayAgent.VPN_GET_PORTAL:
                    case GatewayAgent.VPN_LOGIN:
                    case GatewayAgent.VPN_GET_USERDATA:
                    case GatewayAgent.VPN_HEARTBEAT:
                    case GatewayAgent.VPN_UPDATE_PASSWD_JSON:
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
                        String json = readStr(buffer);
                        JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
                        log.info("handleMsgReq: tag=0x{}, {}", Integer.toHexString(tag), obj == null ? "json=" + HexUtil.encodeHexStr(json) : obj.toString(SerializerFeature.PrettyFormat));
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
                    case 0x504f5354:
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
                    case GatewayAgent.VPN_PRD_DATA: {
                        final int length = dataInput.readInt();
                        final int error = dataInput.readInt();
                        byte[] msg = new byte[length - 4];
                        dataInput.readFully(msg);
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes prd data client error=0x%x, socket=%s", msg.length, error, socket)));
                        }
                        pcap.writePacket(msg);
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
                    case GatewayAgent.VPN_PROXY_ACCESS: {
                        final int length = dataInput.readInt();
                        final int error = dataInput.readInt();
                        byte[] msg = new byte[length - 4];
                        dataInput.readFully(msg);
                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        String ip = readStr(buffer);
                        int port = buffer.getInt();
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes proxy client error=0x%x, proxy=%s:%d, socket=%s", msg.length, error, ip, port, socket)));
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
                    case GatewayAgent.VPN_NC_ACCESS: {
                        final int length = dataInput.readInt();
                        final int error = dataInput.readInt();
                        byte[] msg = new byte[length - 4];
                        dataInput.readFully(msg);
                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        String ipv4 = readStr(buffer);
                        int count = buffer.getInt();
                        List<String> dns4 = new ArrayList<>(count);
                        for (int i = 0; i < count; i++) {
                            dns4.add(readStr(buffer));
                        }
                        count = buffer.getInt();
                        List<String> wins = new ArrayList<>(count);
                        for(int i = 0; i < count; i++) {
                            wins.add(readStr(buffer));
                        }
                        count = buffer.getInt();
                        for(int i = 0; i < count; i++) { // route_assign
                            readStr(buffer);
                            readStr(buffer);
                        }
                        int routeOpt = buffer.getInt();
                        boolean routeAuto = buffer.getInt() != 0;
                        String dnsSuffix = readStr(buffer);
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(msg, String.format("forward %d bytes NC client tag=0x%x, error=0x%x, ipv4=%s, dns4=%s, wins=%s, routeOpt=%d, routeAuto=%s, dnsSuffix=%s, socket=%s, remaining=%d", msg.length, tag, error, ipv4, dns4, wins,
                                    routeOpt, routeAuto, dnsSuffix, socket, buffer.remaining())));
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
                    case GatewayAgent.VPN_GET_PORTAL:
                    case GatewayAgent.VPN_LOGIN:
                    case GatewayAgent.VPN_GET_USERDATA:
                    case GatewayAgent.VPN_HEARTBEAT:
                    case GatewayAgent.VPN_UPDATE_PASSWD_JSON:
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
                            String json = readStr(buffer);
                            JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
                            log.info("handleMsgResp: tag=0x{}, {}\n{}", Integer.toHexString(tag), obj == null ? "json=" + HexUtil.encodeHexStr(json) : obj.toString(SerializerFeature.PrettyFormat),
                                    obj == null ? "json=" + json : obj.toJSONString());
                            JSONArray array = obj == null ? null : obj.getJSONArray("servicelist");
                            if (array != null) {
                                System.out.println("servicelist: " + array.toJSONString());
//                                array.add(0, new Service("Socks", "8.217.195.104", "8.217.195.104").setServicePort(80, Service.AccessType.NC).toJSON(1));
                                obj.put("servicelist", array);
                                System.out.println("userData: " + obj.toJSONString());
                                try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                                    DataOutput dataOutput = new DataOutputStream(baos);
                                    QianxinVPN.writeStr(dataOutput, obj.toJSONString());
                                    msg = baos.toByteArray();
                                }
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

    final void close() {
        IoUtil.close(serverSocket);
    }
}

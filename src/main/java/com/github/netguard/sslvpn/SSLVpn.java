package com.github.netguard.sslvpn;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.Inspector;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tcp.StreamForward;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class SSLVpn extends ProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(SSLVpn.class);
    private static final ServerCertificate SSL_VPN_SERVER_CERTIFICATE = new ServerCertificate("SSLVpn");

    private final Socket socket;
    private final InputStream inputStream;
    private final SSLSocketFactory factory;
    private final int serverPort;

    public SSLVpn(List<ProxyVpn> clients, RootCert rootCert, Socket socket,
                  InputStream inputStream, int serverPort) {
        super(clients, rootCert);
        this.socket = socket;
        this.inputStream = inputStream;
        this.serverPort = serverPort;
        try {
            socket.setSoTimeout(60000);
            SSLContext serverContext = SSL_VPN_SERVER_CERTIFICATE.getServerContext(RootCert.load()).newSSLContext();
            factory = serverContext.getSocketFactory();
        } catch(Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public ClientOS getClientOS() {
        return ClientOS.SSLVpn;
    }

    @Override
    protected void stop() {
        IoUtil.close(socket);
    }

    private static final int USER_ID = 1;
    private static final String GATEWAY_VERSION = "V 5.0 ( 6.2.150.51945 )";

    private boolean canStop;

    @Override
    protected void doRunVpn() {
        try (SSLSocket secureSocket = (SSLSocket) factory.createSocket(socket, inputStream, true)) {
            secureSocket.setUseClientMode(false);

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
            log.debug("handshake completed");

            try (InputStream inputStream = secureSocket.getInputStream();
                 OutputStream outputStream = secureSocket.getOutputStream()) {
                DataInputStream dataInput = new DataInputStream(inputStream);

                while (!canStop) {
                    if (proxyOutputStream != null && proxyBuffer != null) {
                        int read = inputStream.read(proxyBuffer);
                        if (read == -1) {
                            throw new EOFException();
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(Arrays.copyOf(proxyBuffer, read), "forward proxy: " + socket));
                        }
                        proxyOutputStream.write(proxyBuffer, 0, read);
                        proxyOutputStream.flush();
                        continue;
                    }

                    int tag = dataInput.readInt();
                    if (log.isDebugEnabled()) {
                        log.debug("tag=0x{}, socket={}", Integer.toHexString(tag), socket);
                    }

                    switch (tag) {
                        case GatewayAgent.VPN_PRD_DATA: {
                            byte[] msg = readMsg(dataInput);
                            byte[] ip = Arrays.copyOfRange(msg, 4, msg.length);
                            if (log.isTraceEnabled()) {
                                log.trace("{}", Inspector.inspectString(ip, String.format("tag=0x%x, socket=%s, vpnOutputStream=%s", tag, socket, vpnOutputStream)));
                            }
                            DataOutput dataOutput = new DataOutputStream(vpnOutputStream);
                            for (int i = 0; i < ip.length; i++) {
                                ip[i] ^= ServiceSinkhole.VPN_MAGIC;
                            }
                            dataOutput.writeShort(ip.length);
                            dataOutput.write(ip);
                            break;
                        }
                        case GatewayAgent.VPN_PROXY_ACCESS: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleProxyAccess(tag, msg, outputStream);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_NC_ACCESS: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleVpnNcAccess(tag, msg, outputStream);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_HEARTBEAT: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleHeartbeat(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_UPDATE_PASSWD_JSON: {
                            byte[] msg = readMsg(dataInput);
                            ByteBuffer buffer = ByteBuffer.wrap(msg);
                            readJSON(buffer);
                            break;
                        }
                        case GatewayAgent.VPN_QUERY_APP_LIST: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleQueryAppList(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_LOGOUT: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleVpnLogout(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_GET_USERDATA: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleGetUserData(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_LOGIN: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleVpnLogin(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case GatewayAgent.VPN_GET_PORTAL: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleGetPortal(tag, msg);
                            outputStream.write(data);
                            outputStream.flush();
                            break;
                        }
                        case 0x504f5354: // POST
                        case 0x47455420: // GET
                        {
                            try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                                DataOutput dataOutput = new DataOutputStream(baos);
                                dataOutput.writeInt(tag);
                                byte[] header = new byte[12];
                                dataInput.readFully(header);
                                dataOutput.write(header);
                                HttpRequest request = ClientHelloRecord.detectHttp(baos, dataInput);
                                if (request != null) {
                                    HttpResponse response = handleHttpRequest(request);
                                    log.debug("Handle httpResponse: {}", response);
                                    if (response != null) {
                                        writeResponse(outputStream, response);
                                    }
                                }
                            }
                            throw new IOException("NOT support HTTP");
                        }
                        default: {
                            log.warn("unknown tag=0x{}", Integer.toHexString(tag));
                            canStop = true;
                            break;
                        }
                    }
                }
            }
        } catch(IOException e) {
            log.trace("SSL VPN read", e);
        } catch(Exception e) {
            log.warn("SSL VPN failed", e);
        } finally {
            IoUtil.close(proxyOutputStream);
            log.debug("Finish socket: {}", socket);
            clients.remove(this);
        }
    }

    private void writeResponse(OutputStream outputStream, HttpResponse response) throws IOException {
        StringWriter buffer = new StringWriter();
        PrintWriter writer = new PrintWriter(buffer);
        writer.write(response.protocolVersion().toString());
        writer.write(" ");
        writer.write(response.status().toString());
        writer.write("\r\n");
        response.headers().entries().forEach(entry -> {
            writer.write(entry.getKey());
            writer.write(": ");
            writer.write(entry.getValue());
            writer.write("\r\n");
        });
        writer.write("\r\n");
        outputStream.write(buffer.toString().getBytes(StandardCharsets.UTF_8));
        if (response instanceof HttpContent) {
            HttpContent httpContent = (HttpContent) response;
            try(InputStream in = new ByteBufInputStream(httpContent.content())) {
                IoUtil.copy(in, outputStream);
            }
        }
        outputStream.flush();
    }

    private HttpResponse notFound() {
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.add("Connection", "close");
        headers.add("Server", String.format("%s_%s", getClass().getSimpleName(), GATEWAY_VERSION));
        return new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND, headers);
    }

    private HttpResponse fullResponse(String contentType, byte[] data) {
        HttpHeaders headers = new DefaultHttpHeaders();
        if (contentType != null) {
            headers.add("Content-Type", contentType);
        }
        headers.add("Content-Length", String.valueOf(data.length));
        headers.add("Connection", "close");
        headers.add("Server", String.format("%s_%s", getClass().getSimpleName(), GATEWAY_VERSION));
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(data), headers,
                DefaultHttpHeadersFactory.trailersFactory().newEmptyHeaders());
    }

    private HttpResponse handleHttpRequest(HttpRequest request) throws IOException {
        log.debug("handleHttpRequest: {}", request);
        if ("/client/custom_lang.json".equals(request.uri()) ||
                "/download/mobile/software/sslvpn-version.xml".equals(request.uri())) {
            return notFound();
        }
        if ((request.uri().startsWith("/download/mobile/resource/ios/pic/") || request.uri().startsWith("/download/mobile/resource/android/pic/")) &&
                request.uri().endsWith(".png")) {
            try (InputStream in = getClass().getResourceAsStream("ie.png")) {
                if (in == null) {
                    return notFound();
                } else {
                    return fullResponse("image/png", IoUtil.readBytes(in));
                }
            }
        }
        if("/download/mobile/resource/ios/pic/def.json".equals(request.uri()) ||
                "/download/mobile/resource/android/pic/def.json".equals(request.uri())) {
            JSONObject obj = new JSONObject(true);
            obj.put("service_change", 4);
            obj.put("version", 1);
            JSONArray array = new JSONArray();
            for (PicDef def : PicDef.values()) {
                JSONObject item = new JSONObject(2, true);
                item.put("id", def.ordinal() + 1);
                item.put("name", def.name());
                array.add(item);
            }
            obj.put("list", array);
            return fullResponse("application/json; charset=utf-8", obj.toJSONString().getBytes(StandardCharsets.UTF_8));
        }
        return null;
    }

    private byte[] handleGetUserData(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        JSONObject obj = readJSON(buffer);
        final String ticket = obj.getString("ticket");
        if (ticket == null || ticket.length() != 64) {
            return buildErrorResponse(tag | 0x80000000, 0x200043d); // 验证失败，请重试
        }
        JSONObject response = new JSONObject(true);
        response.put("authserid", USER_ID);
        response.put("compress", 0);
        response.put("devtime", System.currentTimeMillis() / 1000);
        response.put("domain", "");
        response.put("expires", 0);
        response.put("gateway_version", GATEWAY_VERSION);
        response.put("gm_port", 0);
        {
            JSONObject hostchecker = new JSONObject(1);
            hostchecker.put("require", "allof");
            response.put("hostchecker", hostchecker);
        }
        response.put("ios_mdm_status", "ios_setup_ok");
        response.put("iphost_list", Collections.emptyList());
        String machineId = DigestUtil.md5Hex16(String.format("%s_%s", getClass().getSimpleName(), GATEWAY_VERSION));
        response.put("machineid", machineId.toUpperCase());
        JSONObject mpolicy = buildMPolicy();
        response.put("mpolicy", mpolicy);
        response.put("need_bind", 0);
        response.put("no_block_header_enabled", 1);
        response.put("prd_port2", 0);
        response.put("proto_version", "2");
        response.put("rdp_optimize", 0);
        response.put("rdpgroup_list", Collections.emptyList());
        response.put("servicegrouplist", Arrays.asList(new Group("1", "默认组"), new Group("2", "自定义组")));
        List<Service> services = Arrays.asList(
                new Service("Test", "183.6.211.61", "2025.ip138.com"),
                new Service("172.18网段", "192.18.0.0-192.18.255.255", "192.18.0.0/255.255.0.0").setHide(),
                new Service("威固报价系统", "10.163.51.119", "10.163.51.119").setServicePort(8080, Service.AccessType.NC),
                new Service("视频监控", "192.168.88.66", "192.168.88.66").setServicePort(8096),
                new Service("Socks", "8.217.195.104", "8.217.195.104").setServicePort(80, Service.AccessType.NC)
        );
        JSONArray array = new JSONArray(services.size());
        int id = 1;
        for (Service service : services) {
            array.add(service.toJSON(id++));
        }
        response.put("servicelist", array);
        response.put("sm_enc_algo", "");
        response.put("split_tunnel_list", "");
        response.put("split_tunnel_open", 0);
        response.put("sso_list", Collections.emptyList());
        response.put("subaccount_list", Collections.emptyList());
        response.put("use_gm_ssl", 0);
        response.put("userid", USER_ID);
        String username;
        String password;
        byte[] ticketData = HexUtil.decodeHex(ticket);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(ticketData)) {
            DataInput in = new DataInputStream(bais);
            username = in.readUTF();
            password = new String(bais.readAllBytes()).trim();
        }
        response.put("username", username);
        response.put("userpass", password);
        response.put("version", "1.0");
        response.put("wol_list", "");
        return buildResponse(tag, response);
    }

    private static final int ERR_PROXY_CONNECT = 0x4000410;

    private OutputStream proxyOutputStream;
    private byte[] proxyBuffer;

    private byte[] handleProxyAccess(int tag, byte[] msg, OutputStream outputStream) throws IOException {
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
        log.debug("{}", Inspector.inspectString(msg, String.format("handleProxyAccess username=%s, version=%d, extFlag=0x%x, svcId=%d, svr_name=%s, svr_ip=%s, svr_port=%s, compress=%d, count=%d, remaining=%d", username,
                version, extFlag, svcId, svr_name, svr_ip, svr_port, compress, count, buffer.remaining())));
        try {
            InetSocketAddress server = new InetSocketAddress("183.6.211.61", 80);
            Socket proxySocket = new Socket();
            proxySocket.connect(server, 10000);

            proxyOutputStream = proxySocket.getOutputStream();
            proxyBuffer = new byte[4096];
            StreamForward outbound = new StreamForward(proxySocket.getInputStream(), outputStream, false, getRemoteSocketAddress(), server, null, proxySocket, null, server.getHostName(), false, null);
            outbound.startThread(null);

            InetSocketAddress address = (InetSocketAddress) proxySocket.getLocalSocketAddress();
            try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                DataOutput dataOutput = new DataOutputStream(baos);
                writeStr(dataOutput, address.getHostString());
                dataOutput.writeInt(address.getPort());
                return buildResponse(tag, baos.toByteArray());
            }
        } catch (IOException e) {
            log.debug("connect failed", e);
            return buildErrorResponse(tag, ERR_PROXY_CONNECT);
        }
    }

    private OutputStream vpnOutputStream;

    private class VpnStreamForward extends StreamForward {
        public VpnStreamForward(Socket vpnSocket, OutputStream outputStream, InetSocketAddress server) throws IOException {
            super(vpnSocket.getInputStream(), outputStream, false, SSLVpn.this.getRemoteSocketAddress(), server, null, vpnSocket, null, server.getHostName(), false, null);
        }
        @Override
        protected boolean forward(byte[] buf) throws IOException {
            DataInput dataInput = new DataInputStream(inputStream);
            int size = dataInput.readUnsignedShort();
            if (size > buf.length) {
                throw new IllegalStateException("VPN stream buffer too long");
            }
            dataInput.readFully(buf, 0, size);
            log.debug("forward vpn ip packet: size={}, buf.length={}", size, buf.length);
            for(int i = 0; i < size; i++) {
                buf[i] ^= ServiceSinkhole.VPN_MAGIC;
            }
            byte[] data = buildResponse(GatewayAgent.VPN_PRD_DATA, buf, size);
            outputStream.write(data);
            outputStream.flush();
            return false;
        }
    }

    private byte[] handleVpnNcAccess(int tag, byte[] msg, OutputStream outputStream) throws IOException {
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

        InetSocketAddress server = new InetSocketAddress("127.0.0.1", serverPort);
        Socket vpnSocket = new Socket();
        vpnSocket.connect(server, 2000);
        vpnOutputStream = vpnSocket.getOutputStream();
        vpnOutputStream.write(ClientOS.QianxinVPN.ordinal());

        StreamForward outbound = new VpnStreamForward(vpnSocket, outputStream, server);
        outbound.startThread(null);

        log.debug("handleVpnNcAccess username={}, password={}, version={}, compress={}, ip={}, remaining={}", username, password, version, compress, ip, buffer.remaining());
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            writeStr(dataOutput, "10.1.10.1");
            List<String> dnsList = Arrays.asList("114.114.114.114", "8.8.8.8");
            dataOutput.writeInt(dnsList.size());
            for (String dns : dnsList) {
                writeStr(dataOutput, dns);
            }
            dataOutput.writeInt(0); // wins
            dataOutput.writeInt(0); // route_assign
            int routeOpt = 0;
            dataOutput.writeInt(routeOpt);
            int routeAuto = 1;
            dataOutput.writeInt(routeAuto);
            String dnsSuffix = "";
            writeStr(dataOutput, dnsSuffix);
            dataOutput.writeInt(0);
            dataOutput.writeInt(0);
            return buildResponse(tag, baos.toByteArray());
        }
    }

    private byte[] handleHeartbeat(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        readJSON(buffer);
        JSONObject response = new JSONObject();
        return buildResponse(tag, response);
    }

    private byte[] handleQueryAppList(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        readJSON(buffer);
        JSONObject response = new JSONObject(1);
        response.put("applist", Collections.emptyList());
        return buildResponse(tag, response);
    }

    private byte[] handleVpnLogout(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        readJSON(buffer);
        JSONObject response = new JSONObject(1);
        response.put("L2TP/PPTP", 0);
        return buildResponse(tag, response);
    }

    private byte[] handleGetPortal(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        readJSON(buffer);
        JSONObject obj = new JSONObject(true);
        JSONArray list = buildAuthList();
        obj.put("AuthList", list);
        JSONObject passwdPolicy = buildPasswdPolicy();
        obj.put("PasswdPolicy", passwdPolicy.toJSONString());
        obj.put("antivirus", 0);
        obj.put("cert_flag", 0);
        obj.put("dns_resolve_once", 1);
        obj.put("find_pwd", 1);
        obj.put("gateway_version", GATEWAY_VERSION);
        obj.put("gm_port", 0);
        obj.put("prd_port2", 0);
        obj.put("show_authen", 0);
        obj.put("sm2_application", "");
        obj.put("sm2_container", "");
        obj.put("sm_cert", 0);
        obj.put("sm_enc_algo", "");
        obj.put("sm_enc_algo_id", 0);
        obj.put("standard_port", serverPort);
        obj.put("terminal_line_type", 31);
        obj.put("use_gm_ssl", 0);
        obj.put("user_reg", 1);
        return buildResponse(tag, obj);
    }

    private static JSONObject buildPasswdPolicy() {
        JSONObject passwdPolicy = new JSONObject(true);
        passwdPolicy.put("pass_min", 6);
        passwdPolicy.put("pass_max", 32);
        passwdPolicy.put("pass_change", 1);
        passwdPolicy.put("pass_warning", 0);
        passwdPolicy.put("first_login", 1);
        passwdPolicy.put("same_pass", 1);
        passwdPolicy.put("number", 1);
        passwdPolicy.put("number_size", 2);
        passwdPolicy.put("up_letter", 1);
        passwdPolicy.put("up_size", 2);
        passwdPolicy.put("low_letter", 1);
        passwdPolicy.put("low_size", 2);
        passwdPolicy.put("spe_letter", 0);
        passwdPolicy.put("spe_size", 0);
        return passwdPolicy;
    }

    private byte[] handleVpnLogin(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        JSONObject obj = readJSON(buffer);
        String username = obj.getString("UserName");
        String password = obj.getString("Password");
        if (log.isDebugEnabled()) {
            log.debug("client_version={}, username={}, password={}", obj.getString("client_version"), username, password);
        }
        JSONObject response = new JSONObject(true);
        response.put("AuthNextFlag", 0);
        response.put("AuthTime", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        response.put("ClientIP", getRemoteSocketAddress().getAddress().getHostAddress());
        response.put("EnableChangePwd", 1);
        response.put("RepeatFlag", 0);
        response.put("SMSAuzFlag", 0);
        response.put("ThisUserID", USER_ID);
        response.put("ThisUserName", username);
        final byte[] ticket;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeUTF(username);
            dataOutput.write((password == null ? "" : password).getBytes());
            ticket = baos.toByteArray();
        }
        response.put("Ticket", HexUtil.encodeHexStr(Arrays.copyOf(ticket, 32)).toUpperCase());
        response.put("UserID", USER_ID);
        response.put("UserLang", 2);
        response.put("UserName", username);
        response.put("UserTimeout", 0);
        response.put("antivirus", 0);
        response.put("gateway_version", GATEWAY_VERSION);
        return buildResponse(tag, response);
    }

    private static JSONObject buildMPolicy() {
        JSONObject mpolicy = new JSONObject(true);
        mpolicy.put("app_device_mdm", 0);
        mpolicy.put("arl", 0);
        mpolicy.put("bind", 0);
        mpolicy.put("control", "");
        mpolicy.put("gesture_enable", 0);
        mpolicy.put("gesture_expires", 0);
        mpolicy.put("gesture_login", 0);
        mpolicy.put("vspace", "");
        return mpolicy;
    }

    private static final byte[] ALIGN_BYTES = new byte[4];

    public static void writeStr(DataOutput dataOutput, String str) throws IOException {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        dataOutput.writeInt(bytes.length);
        dataOutput.write(bytes);
        int off = bytes.length % 4;
        if (off > 0) {
            dataOutput.write(ALIGN_BYTES, 0, 4 - off);
        }
    }

    private byte[] buildResponse(int tag, JSONObject obj) throws IOException {
        canStop = true;
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            writeStr(dataOutput, obj.toJSONString());
            if (log.isDebugEnabled()) {
                log.debug("build response: {}", obj.toString(SerializerFeature.PrettyFormat));
            }
            return buildResponse(tag | 0x80000000, baos.toByteArray());
        }
    }

    private byte[] buildResponse(int tag, byte[] msg) throws IOException {
        return buildResponse(tag, msg, msg.length);
    }

    private byte[] buildResponse(int tag, byte[] msg, int length) throws IOException {
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeInt(tag);
            dataOutput.writeInt(length + 4);
            dataOutput.writeInt(0);
            dataOutput.write(msg, 0, length);
            return baos.toByteArray();
        }
    }

    private byte[] buildErrorResponse(int tag, int error) throws IOException {
        if (error == 0) {
            throw new IllegalArgumentException("Invalid error");
        }
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(12)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeInt(tag);
            dataOutput.writeInt(4);
            dataOutput.writeInt(error);
            return baos.toByteArray();
        }
    }

    private static JSONArray buildAuthList() {
        JSONObject auth = new JSONObject(true);
        auth.put("AuthID", 1);
        auth.put("AuthName", "Any");
        auth.put("IamFlag", 0);
        auth.put("PushFlag", 0);
        auth.put("QrFlag", 0);
        auth.put("SubAuthID", 1);
        auth.put("SubAuthName", "Any");
        auth.put("SubAuthType", 0);
        JSONArray array = new JSONArray(1);
        array.add(auth);
        return array;
    }

    private static JSONObject readJSON(ByteBuffer buffer) {
        String json = readStr(buffer);
        JSONObject obj = JSONObject.parseObject(json, Feature.OrderedField);
        if (log.isDebugEnabled()) {
            log.debug("readJSON={}", obj.toString(SerializerFeature.PrettyFormat));
        }
        return obj;
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

    private byte[] readMsg(DataInput dataInput) throws IOException {
        int length = dataInput.readInt();
        byte[] msg = new byte[length];
        dataInput.readFully(msg);
        if (log.isDebugEnabled()) {
            byte[] tmp = msg;
            if (tmp.length > 32) {
                tmp = Arrays.copyOf(tmp, 32);
            }
            log.debug("{}", Inspector.inspectString(tmp, String.format("readMsg %d bytes, socket=%s", msg.length, socket)));
        }
        return msg;
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

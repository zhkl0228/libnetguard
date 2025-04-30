package com.github.netguard.sslvpn;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.Inspector;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
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

    public SSLVpn(List<ProxyVpn> clients, RootCert rootCert, Socket socket, InputStream inputStream) {
        super(clients, rootCert);
        this.socket = socket;
        this.inputStream = inputStream;
        try {
            SSLContext serverContext = SSL_VPN_SERVER_CERTIFICATE.getServerContext(RootCert.load()).newSSLContext();
            factory = serverContext.getSocketFactory();
        } catch(Exception e) {
            throw new IllegalStateException(e);
        }
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
                    int tag = dataInput.readInt();
                    log.debug("tag=0x{}", Integer.toHexString(tag));

                    switch (tag) {
                        case GatewayAgent.VPN_PRD_DATA: {
                            byte[] msg = readMsg(dataInput);
                            log.warn("{}", Inspector.inspectString(msg, "tag=0x" + Integer.toHexString(tag)));
                            break;
                        }
                        case GatewayAgent.VPN_PROXY_ACCESS: {
                            byte[] msg = readMsg(dataInput);
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
                            log.debug("{}", Inspector.inspectString(msg, String.format("ncProxy username=%s, version=%d, extFlag=0x%x, svcId=%d, svr_name=%s, svr_ip=%s, svr_port=%s, compress=%d, count=%d, remaining=%d", username,
                                    version, extFlag, svcId, svr_name, svr_ip, svr_port, compress, count, buffer.remaining())));
                            break;
                        }
                        case GatewayAgent.VPN_NC_ACCESS: {
                            byte[] msg = readMsg(dataInput);
                            byte[] data = handleVpnNcAccess(tag, msg);
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
                                        log.debug("Response: {}", buffer);
                                        outputStream.write(buffer.toString().getBytes(StandardCharsets.UTF_8));
                                        if (response instanceof HttpContent) {
                                            HttpContent httpContent = (HttpContent) response;
                                            try(InputStream in = new ByteBufInputStream(httpContent.content())) {
                                                IoUtil.copy(in, outputStream);
                                            }
                                        }
                                        outputStream.flush();
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
            log.debug("Finish socket: {}", socket);
            clients.remove(this);
        }
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
        if ("/client/custom_lang.json".equals(request.uri())) {
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
        response.put("machineid", "0022461CA2EF0003");
        JSONObject mpolicy = buildMPolicy();
        response.put("mpolicy", mpolicy);
        response.put("need_bind", 0);
        response.put("no_block_header_enabled", 1);
        response.put("prd_port2", 0);
        response.put("proto_version", "2");
        response.put("rdp_optimize", 0);
        response.put("rdpgroup_list", Collections.emptyList());
        response.put("servicegrouplist", Arrays.asList(new Group("2", "默认组"), new Group("1", "自定义组")));
        List<Service> services = Arrays.asList(
                new Service("172.18网段", "192.18.0.0-192.18.255.255", "192.18.0.0/255.255.0.0"),
                new Service("威固报价系统", "10.163.51.119", "10.163.51.119").setServicePort(8080),
                new Service("视频监控", "192.168.88.66", "192.168.88.66").setServicePort(8096),
                new Service("IP138", "120.39.215.140", "120.39.215.140").setServicePort(80),
                new Service("Test", "120.39.22.140", "120.39.22.140").setServicePort(443)
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

    private byte[] handleVpnNcAccess(int tag, byte[] msg) throws IOException {
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
        log.debug("handleVpnNcAccess username={}, password={}, version={}, compress={}, ip={}, remaining={}", username, password, version, compress, ip, buffer.remaining());
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            writeStr(dataOutput, "172.16.254.10");
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
        obj.put("PasswdPolicy", "{\"pass_min\":6,\"pass_max\":32,\"pass_change\":0,\"pass_warning\":0,\"first_login\":1,\"same_pass\":0,\"number\":1,\"number_size\":2,\"up_letter\":1,\"up_size\":2,\"low_letter\":1,\"low_size\":2,\"spe_letter\":0,\"spe_size\":0}");
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
        obj.put("standard_port", 443);
        obj.put("terminal_line_type", 31);
        obj.put("use_gm_ssl", 0);
        obj.put("user_reg", 1);
        return buildResponse(tag, obj);
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

    private static void writeStr(DataOutput dataOutput, String str) throws IOException {
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
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeInt(tag);
            dataOutput.writeInt(msg.length + 4);
            dataOutput.writeInt(0);
            dataOutput.write(msg);
            return baos.toByteArray();
        }
    }

    private static JSONArray buildAuthList() {
        JSONObject auth = new JSONObject(true);
        auth.put("AuthID", 1);
        auth.put("AuthName", "任意认证");
        auth.put("IamFlag", 0);
        auth.put("PushFlag", 0);
        auth.put("QrFlag", 0);
        auth.put("SubAuthID", 1);
        auth.put("SubAuthName", "任意认证");
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
            log.debug("{}", Inspector.inspectString(tmp, String.format("readMsg %d bytes", msg.length)));
        }
        return msg;
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

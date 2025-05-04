package com.github.netguard.sslvpn.impl;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.IPUtil;
import com.github.netguard.Inspector;
import com.github.netguard.ProxyVpn;
import com.github.netguard.sslvpn.SSLVpn;
import com.github.netguard.sslvpn.qianxin.QianxinVpn;
import com.github.netguard.sslvpn.qianxin.PicDef;
import com.github.netguard.sslvpn.qianxin.Service;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.StreamForward;
import eu.faircode.netguard.Packet;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

public class SSLVpnImpl extends SSLVpn {

    private static final Logger log = LoggerFactory.getLogger(SSLVpnImpl.class);

    private static final int VPN_BUFFER_SIZE = 0x3000;

    public SSLVpnImpl(List<ProxyVpn> clients, RootCert rootCert, Socket socket,
                      InputStream inputStream, int serverPort) {
        super(clients, rootCert, socket, inputStream, serverPort);
    }

    private boolean canStop;

    @Override
    protected void doSSL(SSLSocket socket) throws IOException {
        try (InputStream inputStream = socket.getInputStream();
             OutputStream outputStream = socket.getOutputStream()) {
            DataInputStream dataInput = new DataInputStream(inputStream);

            while (!canStop) {
                if (proxyOutputStream != null && proxyBuffer != null) {
                    final int read = inputStream.read(proxyBuffer);
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

                final int tag = dataInput.readInt();
                if (log.isDebugEnabled()) {
                    log.debug("tag=0x{}, socket={}", Integer.toHexString(tag), socket);
                }

                switch (tag) {
                    case QianxinVpn.VPN_PRD_DATA: {
                        final int length = readMsg(dataInput, vpnBuffer);
                        for (int i = 4; i < length; i++) {
                            vpnBuffer[i] ^= ServiceSinkhole.VPN_MAGIC;
                        }
                        DataOutput dataOutput = new DataOutputStream(vpnOutputStream);
                        dataOutput.writeShort(length - 4);
                        dataOutput.write(vpnBuffer, 4, length - 4);
                        break;
                    }
                    case QianxinVpn.VPN_PROXY_ACCESS: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleProxyAccess(tag, msg, outputStream);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_NC_ACCESS: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleNcAuthorize(tag, msg, outputStream);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_HEARTBEAT: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleHeartbeat(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_PUT_HOSTBIND:
                    case QianxinVpn.VPN_PASSWORD_INIT:
                    case QianxinVpn.VPN_PASSWORD_UPDATE:
                    case QianxinVpn.VPN_UPDATE_PASSWD_JSON: {
                        byte[] msg = readMsg(dataInput);
                        ByteBuffer buffer = ByteBuffer.wrap(msg);
                        readJSON(buffer);
                        break;
                    }
                    case QianxinVpn.VPN_QUERY_APP_LIST: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleQueryAppList(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_LOGOUT: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleVpnLogout(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_GET_USERDATA: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleGetUserData(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_LOGIN: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleVpnLogin(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case QianxinVpn.VPN_GET_PORTAL: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleGetPortal(tag, msg);
                        outputStream.write(data);
                        outputStream.flush();
                        break;
                    }
                    case 0x504f5354: // POST
                    case 0x47455420: // GET
                    {
                        handleHttp(tag, dataInput, outputStream);
                        canStop = true;
                        break;
                    }
                    default: {
                        log.warn("unknown tag=0x{}", Integer.toHexString(tag));
                        canStop = true;
                        break;
                    }
                }
            }
        } finally {
            IoUtil.close(vpnOutputStream);
            IoUtil.close(proxyOutputStream);
        }
    }

    private HttpResponse handleQianxin(HttpRequest request) throws IOException {
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
            JSONObject obj = new JSONObject(3, true);
            obj.put("service_change", 4);
            obj.put("version", 1);
            PicDef[] defs = PicDef.values();
            JSONArray array = new JSONArray(defs.length);
            for (PicDef def : defs) {
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

    private HttpResponse handleATrust(HttpRequest request) throws IOException {
        return null;
    }

    @Override
    protected HttpResponse handleHttpRequest(HttpRequest request) throws IOException {
        HttpResponse response = handleQianxin(request);
        if (response != null) {
            return response;
        }
        return handleATrust(request);
    }

    private byte[] handleGetUserData(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        JSONObject obj = readJSON(buffer);
        final String ticket = obj.getString("ticket");
        if (ticket == null || ticket.length() != 64) {
            return buildErrorResponse(tag | 0x80000000, QianxinVpn.ERR_INVALID_USER);
        }
        JSONObject response = new JSONObject(true);
        response.put("authserid", QianxinVpn.USER_ID);
        response.put("compress", 0);
        response.put("devtime", System.currentTimeMillis() / 1000);
        response.put("domain", "");
        response.put("expires", 0);
        response.put("gateway_version", QianxinVpn.GATEWAY_VERSION);
        response.put("gm_port", 0);
        {
            JSONObject hostchecker = new JSONObject(1);
            hostchecker.put("require", "allof");
            response.put("hostchecker", hostchecker);
        }
        response.put("ios_mdm_status", "ios_setup_ok");
        response.put("iphost_list", Collections.emptyList());
        String machineId = DigestUtil.md5Hex16(String.format("%s_%s", getClass().getSimpleName(), QianxinVpn.GATEWAY_VERSION));
        response.put("machineid", machineId.toUpperCase());
        JSONObject mpolicy = buildMPolicy();
        response.put("mpolicy", mpolicy);
        response.put("need_bind", 0);
        response.put("no_block_header_enabled", 1);
        response.put("prd_port2", 0);
        response.put("proto_version", "2");
        response.put("rdp_optimize", 0);
        response.put("rdpgroup_list", Collections.emptyList());
        response.put("servicegrouplist", Collections.emptyList());
        List<Service> services = new ArrayList<>();
        Service installRootCert = new Service("RootCert", Packet.INSTALL_ROOT_CERT_IP, Packet.INSTALL_ROOT_CERT_IP).setServicePort(Packet.INSTALL_ROOT_CERT_PORT, Service.ServiceType.http);
        installRootCert.setAccessType(Service.AccessType.NC);
        services.add(installRootCert);
        configServices(services);
        JSONArray array = new JSONArray(services.size());
        int id = 1;
        for (Service service : services) {
            array.add(service.toJSON(id));
        }
        response.put("servicelist", array);
        response.put("sm_enc_algo", "");
        response.put("split_tunnel_list", "");
        response.put("split_tunnel_open", 0);
        response.put("sso_list", Collections.emptyList());
        response.put("subaccount_list", Collections.emptyList());
        response.put("use_gm_ssl", 0);
        response.put("userid", QianxinVpn.USER_ID);
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

    private void configServices(List<Service> services) {
        try {
            InetAddress start = InetAddress.getByName("0.0.0.0");
            for (IPUtil.CIDR exclude : getExcludeIPRanges()) {
                for (IPUtil.CIDR include : IPUtil.toCIDR(start, IPUtil.minus1(exclude.getStart()))) {
                    services.add(createService(include));
                }
                start = IPUtil.plus1(exclude.getEnd());
            }
            for (IPUtil.CIDR include : IPUtil.toCIDR("224.0.0.0", "255.255.255.255")) {
                services.add(createService(include));
            }
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private Service createService(IPUtil.CIDR include) {
        String startIp = include.getStart().getHostAddress();
        String ip = String.format("%s-%s", startIp, include.getEnd().getHostAddress());
        long addr = IPUtil.prefix2mask(include.prefix);
        InetAddress address = IPUtil.long2inet(addr);
        if (address == null) {
            throw new IllegalStateException("Invalid include: " + include);
        }
        String name = String.format("%s/%s", startIp, address.getHostAddress());
        Service service = new Service(startIp, ip, name).setHide();
        service.setAccessType(Service.AccessType.NC);
        if (log.isDebugEnabled()) {
            log.debug("createService address={}, prefix={}, include={}, service={}", include.address, include.prefix, include, service.toJSON(0));
        }
        return service;
    }

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
        String svrName = readStr(buffer);
        String svrIp = readStr(buffer);
        String svrPort = readStr(buffer);
        int compress = buffer.getInt();
        int count = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("{}", Inspector.inspectString(msg, String.format("handleProxyAccess username=%s, version=%d, extFlag=0x%x, svcId=%d, svrName=%s, svrIp=%s, svrPort=%s, compress=%d, count=%d, remaining=%d", username,
                    version, extFlag, svcId, svrName, svrIp, svrPort, compress, count, buffer.remaining())));
        }
        try {
            InetSocketAddress server = new InetSocketAddress("183.6.211.61", 80);
            Socket proxySocket = new Socket();
            proxySocket.connect(server, 10000);

            proxyOutputStream = proxySocket.getOutputStream();
            proxyBuffer = new byte[VPN_BUFFER_SIZE];
            StreamForward outbound = new StreamForward(proxySocket.getInputStream(), outputStream, false, getRemoteSocketAddress(), server, null, proxySocket, null, server.getHostName(), false, null) {
                @Override
                protected int getReceiveBufferSize() {
                    return VPN_BUFFER_SIZE;
                }
            };
            outbound.startThread(null);

            InetSocketAddress address = (InetSocketAddress) proxySocket.getLocalSocketAddress();
            try(ByteArrayOutputStream baos = new ByteArrayOutputStream(32)) {
                DataOutput dataOutput = new DataOutputStream(baos);
                writeStr(dataOutput, address.getHostString());
                dataOutput.writeInt(address.getPort());
                return buildResponse(tag, baos.toByteArray());
            }
        } catch (IOException e) {
            log.debug("connect failed", e);
            return buildErrorResponse(tag, QianxinVpn.ERR_PROXY_CONNECT);
        }
    }

    private OutputStream vpnOutputStream;
    private byte[] vpnBuffer;

    private class VpnStreamForward extends StreamForward {
        public VpnStreamForward(Socket vpnSocket, OutputStream outputStream, InetSocketAddress server) throws IOException {
            super(vpnSocket.getInputStream(), outputStream, false, SSLVpnImpl.this.getRemoteSocketAddress(), server, null, vpnSocket, null, server.getHostName(), false, null);
        }
        @Override
        protected int getReceiveBufferSize() {
            return VPN_BUFFER_SIZE;
        }
        @Override
        protected boolean forward(byte[] buf) throws IOException {
            DataInput dataInput = new DataInputStream(inputStream);
            final int size = dataInput.readUnsignedShort();
            if (size > buf.length) {
                throw new IllegalStateException("VPN stream buffer too long");
            }
            dataInput.readFully(buf, 12, size);
            log.debug("forward vpn ip packet: size={}, buf.length={}", size, buf.length);
            for(int i = 0; i < size; i++) {
                buf[i + 12] ^= ServiceSinkhole.VPN_MAGIC;
            }
            ByteBuffer buffer = ByteBuffer.wrap(buf);
            buffer.putInt(QianxinVpn.VPN_PRD_DATA);
            buffer.putInt(size + 4);
            buffer.putInt(0);
            outputStream.write(buf, 0, size + 12);
            outputStream.flush();
            return false;
        }
    }

    private byte[] handleNcAuthorize(int tag, byte[] msg, OutputStream outputStream) throws IOException {
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
        vpnSocket.connect(server, 1000);
        vpnOutputStream = vpnSocket.getOutputStream();
        vpnOutputStream.write(ClientOS.QianxinVPN.ordinal());
        vpnBuffer = new byte[VPN_BUFFER_SIZE];

        StreamForward outbound = new VpnStreamForward(vpnSocket, outputStream, server);
        outbound.startThread(null);

        log.debug("handleNcAuthorize username={}, password={}, version={}, compress={}, ip={}, remaining={}", username, password, version, compress, ip, buffer.remaining());
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(128)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            writeStr(dataOutput, "10.1.10.1");
            dataOutput.writeInt(DNS_LIST.size());
            for (String dns : DNS_LIST) {
                writeStr(dataOutput, dns);
            }
            dataOutput.writeInt(0); // wins
            if (log.isDebugEnabled()) { // unused route_assign
                dataOutput.writeInt(1);
                writeStr(dataOutput, "192.168.1.12"); // start
                writeStr(dataOutput, "192.168.1.18"); // end
            } else {
                dataOutput.writeInt(0); // route_assign
            }
            final int routeOpt = 0;
            dataOutput.writeInt(routeOpt);
            final int routeAuto = log.isDebugEnabled() ? 0 : 1;
            dataOutput.writeInt(routeAuto);
            writeStr(dataOutput, ""); // dnsSuffix
            writeStr(dataOutput, "");
            writeStr(dataOutput, ""); // ipv6: fd00:1:fd00:1:fd00:1:fd00:1
            byte[] data = buildResponse(tag, baos.toByteArray());
            if (log.isDebugEnabled()) {
                log.debug("{}", Inspector.inspectString(data, "handleNcAuthorize"));
            }
            return data;
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
        obj.put("find_pwd", 0);
        obj.put("gateway_version", QianxinVpn.GATEWAY_VERSION);
        obj.put("gm_port", 0);
        obj.put("prd_port2", 0);
        obj.put("show_authen", 0);
        obj.put("sm2_application", "");
        obj.put("sm2_container", "");
        obj.put("sm_cert", 0);
        obj.put("sm_enc_algo", "");
        obj.put("sm_enc_algo_id", 0);
        obj.put("standard_port", serverPort);
        obj.put("terminal_line_type", 0); // 控制是否允许电信网络访问
        obj.put("use_gm_ssl", 0);
        obj.put("user_reg", 0);
        return buildResponse(tag, obj);
    }

    private static JSONObject buildPasswdPolicy() {
        JSONObject policy = new JSONObject(true);
        policy.put("pass_min", 6);
        policy.put("pass_max", 32);
        policy.put("pass_change", 1);
        policy.put("pass_warning", 0);
        policy.put("first_login", 1);
        policy.put("same_pass", 1);
        policy.put("number", 1);
        policy.put("number_size", 2);
        policy.put("up_letter", 1);
        policy.put("up_size", 2);
        policy.put("low_letter", 1);
        policy.put("low_size", 2);
        policy.put("spe_letter", 0);
        policy.put("spe_size", 0);
        return policy;
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
        response.put("EnableChangePwd", 0);
        response.put("RepeatFlag", 0);
        response.put("SMSAuzFlag", 0);
        response.put("ThisUserID", QianxinVpn.USER_ID);
        response.put("ThisUserName", username);
        final byte[] ticket;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeUTF(username);
            dataOutput.write((password == null ? "" : password).getBytes());
            ticket = baos.toByteArray();
        }
        response.put("Ticket", HexUtil.encodeHexStr(Arrays.copyOf(ticket, 32)).toUpperCase());
        response.put("UserID", QianxinVpn.USER_ID);
        response.put("UserLang", 2);
        response.put("UserName", username);
        response.put("UserTimeout", 0);
        response.put("antivirus", 0);
        response.put("gateway_version", QianxinVpn.GATEWAY_VERSION);
        return buildResponse(tag, response);
    }

    private static JSONObject buildMPolicy() {
        JSONObject policy = new JSONObject(true);
        policy.put("app_device_mdm", 0);
        policy.put("arl", 0);
        policy.put("bind", 0);
        policy.put("control", "");
        policy.put("gesture_enable", 0);
        policy.put("gesture_expires", 0);
        policy.put("gesture_login", 0);
        policy.put("vspace", "");
        return policy;
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
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(msg.length + 12)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeInt(tag);
            dataOutput.writeInt(msg.length + 4);
            dataOutput.writeInt(0);
            dataOutput.write(msg);
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
        auth.put("AuthName", "VPN");
        auth.put("IamFlag", 0);
        auth.put("PushFlag", 0);
        auth.put("QrFlag", 0);
        auth.put("SubAuthID", 1);
        auth.put("SubAuthName", "NetGuard");
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

    private int readMsg(DataInput dataInput, byte[] buf) throws IOException {
        int length = dataInput.readInt();
        dataInput.readFully(buf, 0, length);
        if (log.isDebugEnabled()) {
            byte[] tmp = Arrays.copyOf(buf, length);
            if (length > 32) {
                tmp = Arrays.copyOf(tmp, 32);
            }
            log.debug("{}", Inspector.inspectString(tmp, String.format("readMsg %d bytes", length)));
        }
        return length;
    }

}

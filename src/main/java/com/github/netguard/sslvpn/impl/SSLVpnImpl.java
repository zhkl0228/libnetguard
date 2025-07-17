package com.github.netguard.sslvpn.impl;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.file.FileNameUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.IPUtil;
import com.github.netguard.Inspector;
import com.github.netguard.ProxyVpn;
import com.github.netguard.sslvpn.SSLVpn;
import com.github.netguard.sslvpn.qianxin.PicDef;
import com.github.netguard.sslvpn.qianxin.QianxinVpn;
import com.github.netguard.sslvpn.qianxin.Service;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.StreamForward;
import eu.faircode.netguard.Packet;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
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
                    case QianxinVpn.VPN_SECURE_LOGIN: {
                        byte[] msg = readMsg(dataInput);
                        byte[] data = handleVpnSecureLogin(tag, msg);
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
            try (InputStream in = getClass().getResourceAsStream("/com/github/netguard/sslvpn/qianxin/ie.png")) {
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
        if ("/".equals(request.uri())) {
            String userAgent = request.headers().get("User-Agent");
            if (userAgent.contains("aTrustAPP")) {
                HttpHeaders headers = new DefaultHttpHeaders();
                headers.add("Location", "/portal/");
                headers.add("Connection", "close");
                headers.add("Server", getHttpServerName());
                return new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FOUND, headers);
            }
            if ("SPCClientType aTrustTray".equals(userAgent)) {
                JSONObject obj = new JSONObject(1);
                return fullResponse("application/json; charset=utf-8", obj.toJSONString().getBytes(StandardCharsets.UTF_8));
            }
        }
        if("/public/manifest".equals(request.uri())) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"OK\",\"data\":{\"server\":\"aTrust/2.3.10\",\"trustDevice\":{\"enable\":true},\"capacities\":{\"weakPwd\":{\"version\":\"1.0.0.0\"},\"cdn\":{\"version\":\"1.0.0.0\"},\"clientResource\":{\"version\":\"1.0.0.0\",\"appList\":{\"version\":\"1.0.0.0\"},\"spaSeed\":{\"version\":\"1.0.0.0\"},\"openModel\":{\"version\":\"1.0.0.0\"}},\"trustedApplication\":{\"version\":\"1.0.0.1\"},\"adaptiveAuth\":{\"version\":\"1.0.0.1\"},\"antiMITMAttack\":{\"version\":\"1.0.0.3\"},\"verifyInterfaceSig\":{\"version\":\"1.0.0.1\"},\"uemAppStore\":{\"version\":\"1.0.0.2\"},\"standaloneClient\":{\"version\":\"1.0.0.2\"},\"quickSocks5\":{\"version\":\"1.0.0.1\"},\"forgetPassword\":{\"version\":\"1.0.0.0\"},\"appLock\":{\"version\":\"1.0.0.1\"},\"multiSandbox\":{\"version\":\"1.0.0.1\"},\"aioClient\":{\"version\":\"1.0.0.0\"},\"uemAppSso\":{\"version\":\"1.0.0.0\"},\"linuxWorkSpace\":{\"version\":\"1.0.0.0\"},\"simplifyWorkspace\":{\"version\":\"1.0.0.0\"},\"uemVirtualNet\":{\"version\":\"1.0.0.0\"},\"uemAudit\":{\"version\":\"1.0.0.0\"},\"uemShare\":{\"version\":\"1.0.0.0\"},\"recommendApp\":{\"version\":\"1.0.0.0\"},\"onlinePolicy\":{\"version\":\"1.0.0.0\"},\"localClientVersion\":{\"version\":\"1.0.0.0\"},\"quickLogout\":{\"version\":\"1.0.0.0\"}},\"options\":{\"aioClient\":{\"enable\":true}}}}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/public/spaConfig")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"pubKey\":\"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09\",\"pubKeyExp\":\"65537\",\"antiMITMAttackData\":{\"enable\":0,\"devicePubKeyMod\":\"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B\",\"devicePubKeyExp\":\"10001\",\"rsaCert\":\"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=\",\"sm2encCert\":\"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN\",\"challenge\":\"lme8fKYSOYPcCDlxFf+4KYEjWA+al2VDWde/RnUhnO3go3IvrLPfCiRWK6hJBKqYjQ4rCvZNH8+BvBxVBtUVFTBhXmhs+dEnWNAgVecZw4UqaIhX4dqBHDTF26iMz+Kv/Yd6EvZUJokdZM+oaWjzMcz1l/Pp33t3ZdfUjt9x1iA=\",\"encryptedChallenge\":\"814B42E093AF51267BD19E2E502785899508F2B2A25182B308FA30F6CA196D16F1CB64569B7D08A68F2CAC1F48BE37783C71DECA6464013C8092123E200DA4872FB2CF4C61B3D7499B74B400966E2401AE34BC69561A84DA0A75170115F52C583B24A59CB0EDE51EFCEF2949BCC46C281BCA4CF7B05416478D30B12B8F02A77D0226818EB9FB92C233271DE4EBB99B5DC85849D6A1D1D42AC31B522EED958700B472A49D51ED34A0B73B95159C0F60DB\",\"ticket\":\"\",\"antiMITMRequest\":false,\"mitmSig\":\"c9d2497eb8f539ec9b8f35778be3501e6d9140943cef8ee383bca8155af2890f\"},\"udpSpa\":{\"enable\":0,\"encryptedConf\":\"7E9D6C81FC242971A766BF61C18F11369190416B523E760C8E6652A49FF84844717E4414B488CCF1A47BAE146671F47E9A2E306F3DC3386A8E711D06301A927A37E9392AA0295C2110DD5D8AC7C91CC0ECC003F618C6BA345BE08C0FF4E3A104AE47FF18D264E099FE389964AA8B9EF9ADF86C9E2E638D14BA5AEE294CE8DEA47C346D111385EC9012F154B1E58EB0022F8DDF1B14614B309C2E8D9F4EC20E7E89F1F09C075465600D1BB38EC016E26D579B72B108DA4B86E6B881795A3F42A2\",\"sign\":\"764bdc98943048b80ddc8e8eb3988ab68df715d3cae457127a73d0b8fe49edc3\"}},\"traceId\":\"0023dd24a17fe442\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/public/authConfig")) {
            // /passport/v1/public/authConfig?clientType=SangforIdClient&platform=iOS&lang=zh-CN&platformVersion=18.4.1&mobileId=a5dee62c2dd9b6e0688a7e2a9bc1941d&needTicket=0&mod=0
            // {"code":0,"message":"成功","data":{"firstAuth":["auth/psw"],"defaultDomain":"local","domains":["local"],"authServerInfoList":[{"loginDomain":"local","authId":"1","authType":"auth/psw","subType":"default","authName":"本地密码认证","description":"","iconPath":"/portal/icon/auth_server/auth_psw_default.svg","loginUrl":"","logoutUrl":""}],"pubKey":"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09","pubKeyExp":"65537","antiReplayRand":"afece84718e4b100","clientVerifyCode":"f84a5fd8-ee8d-4b9f-95a3-791ce78ada2d","clientInstallMode":"noUse","enableClientAutoStart":"0","guid":"283ed9ec52fbe2f43bf2b7c54e1485ade815b2894651cd3d00e81aa17fc7d81a","passportTokenEnable":0,"qyWechatQrcodeConf":{},"dingTalkQrcodeConf":{},"thirdAuthQrcodeTimeout":60,"security":{"csrfToken":"8afc4e54-6268-4e7c-8b7c-17b754169d7c"},"portalProtocolKey":"1c243f98dfc0de274a4d6c7aed8712e9e4b5e83f32338f0e7b5b80f2cea59097","antiMITMAttackData":{"enable":0,"devicePubKeyMod":"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B","devicePubKeyExp":"10001","rsaCert":"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=","sm2encCert":"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN","challenge":"oNIM8tD4CvBtLqRqmw8/Yjfi21afpRIZS12I6VmSPiB0JQlSrbmHwmiGOhtiKroDpgtnZgGPoyAJeRrM0kAvjvbkO+anY9NcHYuzhksoJr0DrwnL2IaV1LnawuJ2BflM44gXVyVGAEBRGI7ubMtZaHWZK3dEFLCIVhOnL44mHTU=","encryptedChallenge":"01DB6B8C0A6071E25F5BD1026B322093806ED39CAA2A760D4B9473FA3A7085EC18D7F6DF13153F12531FE0D17BE962EB40F1FD7A9D45786E038BA7F1614B022C2AEF0CEF02607311CCF058B5FF6564CD838B70B7347D1A7EE45B30D57906BD51A705D5CF580B5AABA55A6537AC51F43E5AE367DDEFE2923C7A136BBD493CED63659CF710078769A748AC5588E88DE343AF3C97B7D7E1A7E53D7AA5D76D51B9DC37BE17A8C1CC4E498F83FA562E70F262","ticket":"","antiMITMRequest":false,"mitmSig":"ad7f084df618f4e41293d1e9bc793a7264ed204ebe0b2da5d2377c7a73bafa5b"},"certData":{"enable":1,"certList":[]},"usbKeyData":{"enable":0,"usbKeyList":[]},"webDiagnosisConf":{"enable":false},"autoRedirect":true,"appCenterConfig":{"viewModel":"icon"},"rememberPwdConfig":{},"qyWechatAuthScenario":{},"dingTalkAuthScenario":{},"skipAppCenterEnable":"0","enableClientForceUpdate":"0","isLogin":0,"certDomains":[]},"traceId":"0013a9c4d5b41f60"}

            // /passport/v1/public/authConfig?clientType=SangforIdClient&platform=iOS&lang=zh-CN&platformVersion=18.4.1&mobileId=a5dee62c2dd9b6e0688a7e2a9bc1941d&needTicket=0
            // {"code":0,"message":"成功","data":{"firstAuth":["auth/psw"],"defaultDomain":"local","domains":["local"],"authServerInfoList":[{"loginDomain":"local","authId":"1","authType":"auth/psw","subType":"default","authName":"本地密码认证","description":"","iconPath":"/portal/icon/auth_server/auth_psw_default.svg","loginUrl":"","logoutUrl":""}],"pubKey":"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09","pubKeyExp":"65537","antiReplayRand":"35a5c8117f3e1be0","clientVerifyCode":"98ea6651-5264-44ba-819a-6ba57523de00","clientInstallMode":"noUse","enableClientAutoStart":"0","guid":"283ed9ec52fbe2f43bf2b7c54e1485ade815b2894651cd3d00e81aa17fc7d81a","passportTokenEnable":0,"qyWechatQrcodeConf":{},"dingTalkQrcodeConf":{},"thirdAuthQrcodeTimeout":60,"security":{"csrfToken":"7ee40d33-6627-4270-9a3f-e598df199662"},"portalProtocolKey":"1c243f98dfc0de274a4d6c7aed8712e9e4b5e83f32338f0e7b5b80f2cea59097","antiMITMAttackData":{"enable":0,"devicePubKeyMod":"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B","devicePubKeyExp":"10001","rsaCert":"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=","sm2encCert":"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN","challenge":"TQOfsXWxUKZfkzXsfPS6pi/mGAwvUiVXv4omOIdgjX0I3+P7idjJB+U0vuDdwikp/MWDr1FqrOm6pbL3l4H+uJoTXsQdkx3qO+XQ6T4JYtsXavsIkzEGbU1c8dX66F/5aab9cwIb3WbEOLiBGChnmIv3h98DSzdRMhU6W7OPYEE=","encryptedChallenge":"1BDF371A220E764623A810FBCADF85BE0D90087CE423366E53D14CEF9B199C43F3C0625862151848EE6A1856808EEE697056034240402E5CB8D4C70E5CAD44A6540DDA50911AB1E05B33F7AAC6214CC05ACAF8BF3034B88A8DE8F7A5F07A5C1669B6137AF6D39EDD11070489521E04447730F9FB6753190A524C792F7DF9771A0674C5CCD1881B698BD9EF81B824209033A5D076222D7E4998B3162CE75E256CCA5DAC79FB8E6D531A990D6FAB5DC8D2","ticket":"","antiMITMRequest":false,"mitmSig":"e6deba610303b70458c64cc84be7b0f30d23980b23dd9051db94a2fb88a22363"},"certData":{"enable":1,"certList":[]},"usbKeyData":{"enable":0,"usbKeyList":[]},"webDiagnosisConf":{"enable":false},"autoRedirect":true,"appCenterConfig":{"viewModel":"icon"},"rememberPwdConfig":{},"qyWechatAuthScenario":{},"dingTalkAuthScenario":{},"skipAppCenterEnable":"0","enableClientForceUpdate":"0","isLogin":0,"certDomains":[]},"traceId":"002eea22473a7e9c"}

            // /passport/v1/public/authConfig?clientType=MobileClient&platform=iOS&lang=zh-CN&needTicket=0
            // {"code":0,"message":"成功","data":{"firstAuth":["auth/psw","auth/qrcode"],"defaultDomain":"local","domains":["local"],"authServerInfoList":[],"pubKey":"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09","pubKeyExp":"65537","antiReplayRand":"086ae29fcdcbfb3b","clientVerifyCode":"aee4549b-4289-418b-8bca-878ce8ee843b","clientInstallMode":"noUse","enableClientAutoStart":"0","guid":"283ed9ec52fbe2f43bf2b7c54e1485ade815b2894651cd3d00e81aa17fc7d81a","passportTokenEnable":0,"qyWechatQrcodeConf":{},"dingTalkQrcodeConf":{},"thirdAuthQrcodeTimeout":60,"security":{"csrfToken":"7ee40d33-6627-4270-9a3f-e598df199662"},"portalProtocolKey":"1c243f98dfc0de274a4d6c7aed8712e9e4b5e83f32338f0e7b5b80f2cea59097","antiMITMAttackData":{"enable":0,"devicePubKeyMod":"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B","devicePubKeyExp":"10001","rsaCert":"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=","sm2encCert":"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN","challenge":"Q0j2xL+wAlMs5juAn4+Ww4/bw5GHWYU7DqscsqcR3wxQWBm1pOEZp8IL/NiI7axKd9y1MRKEX+n8BandaxcK2PGB8/Juq4ZfPUPR7gtczgkSBw4nVqOrsa8JcOLJM/vC0zCWMRJcYhoNPt1Lj0tBsFDvmSsTIurl5lJzlMWRIUQ=","encryptedChallenge":"3903A21DF5DB3815AE356B312F27695978A491A1305F08924BE9AFB14A99945B30CE41C9AA53E59E1A341E7B0ACD041E40634B90C373434E5E4904097235CD81548B696E60FBEFF913BCE45012CF59413BA37D368ADCB34F1FEBF33FA4703A3414D6829884F8B536FE9AFD81E7C99215D13BB9EE7796D186625FFCD25F180CBCB759ACE3BAD86CBBE0F6BABE08C8DB1A9A3268F808C826639908EFCA9F4CF4A848BDBF6AD1AE45BCFB2EEDCDB9D04401","ticket":"","antiMITMRequest":false,"mitmSig":"cc52b8bd3590d2f8d344c34a5173d39b2430af4547115975b55db87bb66341c6"},"certData":{"enable":1,"certList":[]},"usbKeyData":{"enable":0,"usbKeyList":[]},"webDiagnosisConf":{"enable":false},"autoRedirect":false,"appCenterConfig":{"viewModel":"icon"},"rememberPwdConfig":{},"qyWechatAuthScenario":{},"dingTalkAuthScenario":{},"skipAppCenterEnable":"0","enableClientForceUpdate":"0","isLogin":0,"certDomains":[]},"traceId":"00ccb56220aadfe1"}

            JSONObject obj;
            if (request.uri().contains("mobileId")) {
                obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"firstAuth\":[\"auth/psw\"],\"defaultDomain\":\"local\",\"domains\":[\"local\"],\"authServerInfoList\":[{\"loginDomain\":\"local\",\"authId\":\"1\",\"authType\":\"auth/psw\",\"subType\":\"default\",\"authName\":\"本地密码认证\",\"description\":\"\",\"iconPath\":\"/portal/icon/auth_server/auth_psw_default.svg\",\"loginUrl\":\"\",\"logoutUrl\":\"\"}],\"pubKey\":\"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09\",\"pubKeyExp\":\"65537\",\"antiReplayRand\":\"afece84718e4b100\",\"clientVerifyCode\":\"f84a5fd8-ee8d-4b9f-95a3-791ce78ada2d\",\"clientInstallMode\":\"noUse\",\"enableClientAutoStart\":\"0\",\"guid\":\"283ed9ec52fbe2f43bf2b7c54e1485ade815b2894651cd3d00e81aa17fc7d81a\",\"passportTokenEnable\":0,\"qyWechatQrcodeConf\":{},\"dingTalkQrcodeConf\":{},\"thirdAuthQrcodeTimeout\":60,\"security\":{\"csrfToken\":\"8afc4e54-6268-4e7c-8b7c-17b754169d7c\"},\"portalProtocolKey\":\"1c243f98dfc0de274a4d6c7aed8712e9e4b5e83f32338f0e7b5b80f2cea59097\",\"antiMITMAttackData\":{\"enable\":0,\"devicePubKeyMod\":\"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B\",\"devicePubKeyExp\":\"10001\",\"rsaCert\":\"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=\",\"sm2encCert\":\"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN\",\"challenge\":\"oNIM8tD4CvBtLqRqmw8/Yjfi21afpRIZS12I6VmSPiB0JQlSrbmHwmiGOhtiKroDpgtnZgGPoyAJeRrM0kAvjvbkO+anY9NcHYuzhksoJr0DrwnL2IaV1LnawuJ2BflM44gXVyVGAEBRGI7ubMtZaHWZK3dEFLCIVhOnL44mHTU=\",\"encryptedChallenge\":\"01DB6B8C0A6071E25F5BD1026B322093806ED39CAA2A760D4B9473FA3A7085EC18D7F6DF13153F12531FE0D17BE962EB40F1FD7A9D45786E038BA7F1614B022C2AEF0CEF02607311CCF058B5FF6564CD838B70B7347D1A7EE45B30D57906BD51A705D5CF580B5AABA55A6537AC51F43E5AE367DDEFE2923C7A136BBD493CED63659CF710078769A748AC5588E88DE343AF3C97B7D7E1A7E53D7AA5D76D51B9DC37BE17A8C1CC4E498F83FA562E70F262\",\"ticket\":\"\",\"antiMITMRequest\":false,\"mitmSig\":\"ad7f084df618f4e41293d1e9bc793a7264ed204ebe0b2da5d2377c7a73bafa5b\"},\"certData\":{\"enable\":1,\"certList\":[]},\"usbKeyData\":{\"enable\":0,\"usbKeyList\":[]},\"webDiagnosisConf\":{\"enable\":false},\"autoRedirect\":true,\"appCenterConfig\":{\"viewModel\":\"icon\"},\"rememberPwdConfig\":{},\"qyWechatAuthScenario\":{},\"dingTalkAuthScenario\":{},\"skipAppCenterEnable\":\"0\",\"enableClientForceUpdate\":\"0\",\"isLogin\":0,\"certDomains\":[]},\"traceId\":\"0013a9c4d5b41f60\"}", Feature.OrderedField);
            } else {
                obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"firstAuth\":[\"auth/psw\",\"auth/qrcode\"],\"defaultDomain\":\"local\",\"domains\":[\"local\"],\"authServerInfoList\":[],\"pubKey\":\"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09\",\"pubKeyExp\":\"65537\",\"antiReplayRand\":\"086ae29fcdcbfb3b\",\"clientVerifyCode\":\"aee4549b-4289-418b-8bca-878ce8ee843b\",\"clientInstallMode\":\"noUse\",\"enableClientAutoStart\":\"0\",\"guid\":\"283ed9ec52fbe2f43bf2b7c54e1485ade815b2894651cd3d00e81aa17fc7d81a\",\"passportTokenEnable\":0,\"qyWechatQrcodeConf\":{},\"dingTalkQrcodeConf\":{},\"thirdAuthQrcodeTimeout\":60,\"security\":{\"csrfToken\":\"7ee40d33-6627-4270-9a3f-e598df199662\"},\"portalProtocolKey\":\"1c243f98dfc0de274a4d6c7aed8712e9e4b5e83f32338f0e7b5b80f2cea59097\",\"antiMITMAttackData\":{\"enable\":0,\"devicePubKeyMod\":\"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B\",\"devicePubKeyExp\":\"10001\",\"rsaCert\":\"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=\",\"sm2encCert\":\"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN\",\"challenge\":\"Q0j2xL+wAlMs5juAn4+Ww4/bw5GHWYU7DqscsqcR3wxQWBm1pOEZp8IL/NiI7axKd9y1MRKEX+n8BandaxcK2PGB8/Juq4ZfPUPR7gtczgkSBw4nVqOrsa8JcOLJM/vC0zCWMRJcYhoNPt1Lj0tBsFDvmSsTIurl5lJzlMWRIUQ=\",\"encryptedChallenge\":\"3903A21DF5DB3815AE356B312F27695978A491A1305F08924BE9AFB14A99945B30CE41C9AA53E59E1A341E7B0ACD041E40634B90C373434E5E4904097235CD81548B696E60FBEFF913BCE45012CF59413BA37D368ADCB34F1FEBF33FA4703A3414D6829884F8B536FE9AFD81E7C99215D13BB9EE7796D186625FFCD25F180CBCB759ACE3BAD86CBBE0F6BABE08C8DB1A9A3268F808C826639908EFCA9F4CF4A848BDBF6AD1AE45BCFB2EEDCDB9D04401\",\"ticket\":\"\",\"antiMITMRequest\":false,\"mitmSig\":\"cc52b8bd3590d2f8d344c34a5173d39b2430af4547115975b55db87bb66341c6\"},\"certData\":{\"enable\":1,\"certList\":[]},\"usbKeyData\":{\"enable\":0,\"usbKeyList\":[]},\"webDiagnosisConf\":{\"enable\":false},\"autoRedirect\":false,\"appCenterConfig\":{\"viewModel\":\"icon\"},\"rememberPwdConfig\":{},\"qyWechatAuthScenario\":{},\"dingTalkAuthScenario\":{},\"skipAppCenterEnable\":\"0\",\"enableClientForceUpdate\":\"0\",\"isLogin\":0,\"certDomains\":[]},\"traceId\":\"00ccb56220aadfe1\"}", Feature.OrderedField);
            }
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/portal/theme/manifest.json")) {
            JSONObject obj = JSON.parseObject("{\"background\":\"login_bg.png\",\"logo\":\"logo.png\",\"clientLoginBg\":\"client_login_bg.png\",\"clientLoginBgEn\":\"client_login_bg_en.png\",\"organizeName\":\"\",\"noticeTitle\":\"温馨提示\",\"serviceTips\":\"\",\"loginTips\":\"欢迎使用零信任，重塑安全边界\",\"loginAgreement\":true,\"downloadClient\":true,\"externalLinks\":[],\"externalLinkTitle\":\"更多\",\"appBackground\":\"service_bg.png\",\"logoIcon\":\"logo_icon.png\",\"appCenterTitle\":\"工作台\",\"appApply\":true,\"appNoAvailableTip\":\"未配置应用\",\"appAllHideTip\":\"应用已隐藏\",\"title\":\"aTrust\",\"clientName\":\"aTrust\",\"rand\":\"00000000\",\"filingInformation\":\"\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/auth/psw")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"密码认证成功\",\"data\":{\"currentService\":\"auth/psw\",\"ticket\":\"d381418b-c624-4635-82d0-72f9235fb270_52655252-bc4c-4d70-abfc-862c32660555\",\"env\":{\"need\":true,\"timing\":\"pre-login\"},\"defaultRedirectUrl\":\"\",\"antiReplayRand\":\"0e659a8495dcc883\",\"nextService\":\"auth/sangforId\",\"userName\":\"zhkl0228\",\"displayName\":\"zhkl0228\"},\"traceId\":\"005686324ac7e3f2\"}", Feature.OrderedField);
            HttpResponse response = handleATrust(request, obj);
            HttpHeaders headers = response.headers();
            headers.add("Set-Cookie", "sid=d381418b-c624-4635-82d0-72f9235fb270_e98bd61c-bb1f-4f7c-aec4-56deb225c632; path=/; samesite=none; secure; httponly");
            return response;
        }
        if (request.uri().startsWith("/controller/v1/public/endpointStrategy")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"data\":{\"env\":[],\"interval\":60,\"reportItems\":[],\"ticket\":\"d381418b-c624-4635-82d0-72f9235fb270_52655252-bc4c-4d70-abfc-862c32660555\"},\"message\":\"OK\",\"traceId\":\"00e196fbae7219b5\"}", Feature.OrderedField);
            HttpResponse response = handleATrust(request, obj);
            response.headers().add("X-Sdp-Random", "XnlUeHKOn6HS33Tt");
            return response;
        }
        if(request.uri().startsWith("/controller/v1/public/reportEnv")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"data\":{},\"message\":\"OK\",\"traceId\":\"008c8978d10a2432\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/auth/sangforId")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"sangforId\":\"da9ff5a2-e004-45e4-aa57-04a3f0a0f736\",\"defaultRedirectUrl\":\"\",\"currentService\":\"auth/sangforId\",\"nextService\":\"\",\"userName\":\"zhkl0228\",\"displayName\":\"zhkl0228\"},\"traceId\":\"005386681a9bd7a2\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/auth/passportTokenOnline")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"sangforIdEnable\":1,\"ticket\":\"d381418b-c624-4635-82d0-72f9235fb270_7b75cca4-b628-47b7-94bd-c7c555f7e903\",\"env\":{\"need\":true,\"timing\":\"pre-login\"},\"sidTicket\":\"d381418b-c624-4635-82d0-72f9235fb270_287569bb-0c85-4e3a-9332-537795ce45a9\",\"defaultRedirectUrl\":\"\",\"currentService\":\"auth/passportTokenOnline\",\"nextService\":\"\",\"userName\":\"zhkl0228\",\"displayName\":\"zhkl0228\"},\"traceId\":\"00f8a9c9bf0e0540\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/controller/v1/user/reportEnv")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"data\":{},\"message\":\"OK\",\"traceId\":\"003d982d00a174e9\"}", Feature.OrderedField);
            HttpResponse response = handleATrust(request, obj);
            response.headers().add("X-Sdp-Random", "JGnayKirQ1OeccCV");
            return response;
        }
        if (request.uri().startsWith("/controller/v1/user/clientResource")) {
            JSONObject obj = JSON.parseObject("{\"resourceType\":{\"emmPolicy\":{\"audit\":{},\"auditCenter\":{},\"sso\":{}},\"globalPolicy\":{\"securityStrategy\":{\"mobileConfig\":{}}},\"sdpPolicy\":{},\"featureCenter\":{}}}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/controller/v1/user/appList")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"data\":{\"appInfo\":[{\"parentGroupId\":\"root\",\"name\":\"默认分类\",\"description\":\"默认分类,不可删除\",\"sequenceNumber\":\"1\",\"status\":\"1\",\"grpid\":\"default\",\"apps\":[{\"id\":\"183992a0-28c5-11f0-b4a8-536ce3d58558\",\"status\":1,\"accessModel\":\"L3VPN\",\"subModel\":\"L3VPN\",\"name\":\"RootCert\",\"description\":\"\",\"groupId\":\"default\",\"accessAddress\":\"http://88.88.88.88:88\",\"level\":\"3\",\"service\":\"\",\"nodeGroupId\":\"162a5d3c-2266-4643-9c50-c5e619fa7e6e\",\"baselineStatus\":0,\"allowApply\":0,\"icon\":{\"type\":\"font\",\"path\":\"\\u0026#xe6dc;\"},\"iconv2\":{\"id\":\"1\",\"path\":\"/portal/preset_icon/batch333_000.png\",\"type\":\"font\"},\"addressList\":[{\"protocol\":\"tcp\",\"port\":\"88\",\"host\":\"88.88.88.88\"}],\"excludeAddressList\":[],\"nodeGroup\":{\"addresses\":[\"{{sdpcHost}}\"]},\"nodeGroupV2\":{\"lan\":[\"{{sdpcHost}}\"],\"wan\":[\"{{sdpcHost}}\"]},\"ext\":{\"dnsProxy\":{\"enable\":0,\"enableLan\":0,\"enableWan\":0},\"hide\":0,\"ipStatus\":0,\"linkageDeviceInfo\":{\"id\":\"\",\"name\":\"\"},\"panConf\":{\"domain\":\"\",\"path\":\"\",\"port\":\"\",\"scheme\":\"https\"},\"readXFF\":0,\"recommendApp\":0,\"security\":{\"netZone\":{\"enable\":0},\"watermark\":{\"enable\":0}}},\"ssoConfig\":{\"enable\":false,\"mode\":\"intelligent\",\"oauth2\":{\"appId\":\"\",\"mode\":\"302\"},\"type\":\"oauth2\"},\"domainList\":[],\"webRelativeDomainList\":[\"http://88.88.88.88:88\"],\"extendModel\":\"\",\"enableTCPPrefL3\":false,\"addrPretend\":false,\"openModel\":null,\"associated\":true,\"areaAllow\":true,\"isFavorite\":false},{\"id\":\"3b69c060-28c5-11f0-b4a8-536ce3d58558\",\"status\":1,\"accessModel\":\"L3VPN\",\"subModel\":\"L3VPN\",\"name\":\"Test\",\"description\":\"\",\"groupId\":\"default\",\"accessAddress\":\"\",\"level\":\"3\",\"service\":\"\",\"nodeGroupId\":\"162a5d3c-2266-4643-9c50-c5e619fa7e6e\",\"baselineStatus\":0,\"allowApply\":0,\"icon\":{\"type\":\"font\",\"path\":\"\\u0026#xe6dc;\"},\"iconv2\":{\"id\":\"1\",\"path\":\"/portal/preset_icon/batch333_000.png\",\"type\":\"font\"},\"addressList\":[{\"protocol\":\"all\",\"port\":\"1-65535\",\"host\":\"0.0.0.0/0\"}],\"excludeAddressList\":[],\"nodeGroup\":{\"addresses\":[\"{{sdpcHost}}\"]},\"nodeGroupV2\":{\"lan\":[\"{{sdpcHost}}\"],\"wan\":[\"{{sdpcHost}}\"]},\"ext\":{\"dnsProxy\":{\"enable\":0,\"enableLan\":0,\"enableWan\":0},\"hide\":1,\"ipStatus\":0,\"linkageDeviceInfo\":{\"id\":\"\",\"name\":\"\"},\"panConf\":{\"domain\":\"\",\"path\":\"\",\"port\":\"\",\"scheme\":\"https\"},\"readXFF\":0,\"recommendApp\":0,\"security\":{\"netZone\":{\"enable\":0},\"watermark\":{\"enable\":0}}},\"ssoConfig\":{\"enable\":false,\"mode\":\"intelligent\",\"oauth2\":{\"appId\":\"3b69c060-28c5-11f0-b4a8-536ce3d58558\",\"mode\":\"302\"},\"type\":\"oauth2\"},\"domainList\":[],\"webRelativeDomainList\":[\"\"],\"extendModel\":\"\",\"enableTCPPrefL3\":false,\"addrPretend\":false,\"openModel\":{\"model\":\"no\",\"issuerName\":[],\"originalFilename\":\"\",\"processName\":\"\",\"programName\":\"\",\"useDefaultBrowser\":0},\"associated\":true,\"areaAllow\":true,\"isFavorite\":false}],\"workspaceId\":\"\",\"workspaceName\":\"\",\"createAt\":1720417620}],\"config\":{\"clientAccessConf\":{\"clientAccessList\":[]},\"nodeGroupConf\":{\"nodeGroupList\":[{\"addressInfo\":[{\"address\":\"{{sdpcHost}}\",\"type\":\"lan\"},{\"address\":\"{{sdpcHost}}\",\"type\":\"wan\"}],\"id\":\"162a5d3c-2266-4643-9c50-c5e619fa7e6e\",\"name\":\"Default\",\"routeStrategy\":{\"algoConfig\":{\"delayThreshold\":100,\"enableDnsLB\":false},\"changeCondition\":{\"delay\":200,\"detectionInterval\":30,\"detectionTimes\":3,\"disableTCPTunnel\":false,\"jitter\":\"\",\"packetLossRate\":\"\"},\"routeMode\":\"delayFirst\"}}]},\"panConf\":{\"enable\":false},\"ssoEnable\":true}},\"message\":\"OK\",\"traceId\":\"00c35b25b3e4d079\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/passport/v1/user/onlineInfo")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"username\":\"zhkl0228\",\"displayName\":\"zhkl0228\",\"isOnline\":true,\"domain\":\"local\",\"authType\":\"other\",\"authInfoUkey\":{},\"userId\":\"6b53cb00-28c4-11f0-b4a8-536ce3d58558\",\"clientIp\":\"192.168.31.181\",\"loginTime\":\"2025-05-04 17:19:11\",\"trustLevel\":null,\"description\":null,\"canModifyPwd\":true,\"userInfo\":{\"phone\":\"\",\"email\":\"\",\"expireTime\":\"永不过期\"},\"defaultRedirectUrl\":\"\",\"dapKvsEnabled\":false,\"path\":\"/\"},\"traceId\":\"0053876b94214663\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/controller/v1/user/spaConfig")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{\"pubKey\":\"D17F9A5C1FC6B73B4CBA92C0E172414E869EA36C58ABDE8E67B628EE7B0992D0F8EB985E6F0A517B706DB930EDE99A66585BB0E4D61CB7B7CD364F185DCB49CA37CF4D3B3F1B4CD35526C5CFD0E41EC0E0E0322B1237C2D4F0BF3A8899A1ACA8F99D85E8A6C77383D0ED398DD39CC991BBE410F4F0F2D82A093B9FE5B118BDD8275367C29729AA1B89652339ADE3C7B2EB2C7EA66386540EFF5333856E97FFC420D53950547FABDE61AF95E90F97975958503F7D78300011092AF58BD15FAFEE329089CD327803AD524A80AE76517FA410C808F25A861B83BC500C5D3F15E3A5A6F6C58568CB7776EBE4E3AFCD19654B11E52C671BE824958EDFF7B5A4E55A09\",\"pubKeyExp\":\"65537\",\"antiMITMAttackData\":{\"enable\":0,\"antiMITMRequest\":false,\"devicePubKeyMod\":\"C2A937C01E3ED91D7925DBACB918C24FAC1754DB0ABC3010CC6E9076ED2FA22B6FA58A93D1EC3F43D45411F31D027885E85137B367C1B65ECBA125D6E972E3C479CAD12B9ED4E83C84064DAC1A1F08A60D049BBDDF2BF2A9C09B81741E1B17DC780BA8070E5960C0248F831092DFF4A2A36C101E3BDD8BB2C1ABCBD6DC90018263B835074F08E289C0501EB16E6C2BB4AC5ECCF6DD53976FC49148E7A9DD6903E25C7C82A04A30FA4F3D6B0472EAB01BAFBEEA280D756946EC7A32DF30374E9054D077693C8A8112561AF77780ADFB9286FB100FEDC7E9EF4031BA1070905A469BB83A5C4E0EF8DFB5A472DAC6D9898910430C244BA0E89DE02D1053C212C60B\",\"devicePubKeyExp\":\"10001\",\"rsaCert\":\"MIIDkTCCAnmgAwIBAgIUc92OAo4DcFIWK1mi/utrpMROZqQwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKpN8AePtkdeSXbrLkYwk+sF1TbCrwwEMxukHbtL6Irb6WKk9HsP0PUVBHzHQJ4hehRN7NnwbZey6El1uly48R5ytErntToPIQGTawaHwimDQSbvd8r8qnAm4F0HhsX3HgLqAcOWWDAJI+DEJLf9KKjbBAeO92LssGry9bckAGCY7g1B08I4onAUB6xbmwrtKxezPbdU5dvxJFI56ndaQPiXHyCoEow+k89awRy6rAbr77qKA11aUbsejLfMDdOkFTQd2k8ioESVhr3d4Ct+5KG+xAP7cfp70AxuhBwkFpGm7g6XE4O+N+1pHLaxtmJiRBDDCRLoOid4C0QU8ISxgsCAwEAAaNHMEUwFgYDVR0RBA8wDYILc2RwLnNzbC5jb20wIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK4qZPm/+PfRSBWtzLp4DoEhZxrl81Bffqr8kYJiDVvtjmQKs5qUSaaNvyK2TxsXlo14qXH3aDgD4/sS/giTcc+BPZCTnJRFzC96Sgbq5O+8aVJhjhQEFeE1Y6dQ3og7gHrBmaq07DEiojGdqORwprtyltSJRdBVXvzYxtiEHYcC44F2ctF+KNl5xwD+KIaiA8UvYcuCS1LPJEFzFqsHZv+tmXKs1A7yFlkmGozTT1oKnSxJNXRmULP8q0aDf6L/CzipzigqnMvh42rgSnmOMn/IWFG8VE5lvSPNd2fXrn5G81TCtCSnKvTzTPuNo8Uq9jAW2XRs/0EcLqqieU82Ppo=\",\"sm2encCert\":\"MIIB3zCCAYSgAwIBAgIUDPqnb1mzeWIXOuKdAgGtRT932YgwCgYIKoEcz1UBg3UwXjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1bmFuMREwDwYDVQQHDAhDaGFuZ3NoYTEQMA4GA1UECgwHU2FuZ2ZvcjEMMAoGA1UECwwDU1NMMQwwCgYDVQQDDANzZHAwHhcNMjUwNTAxMjA1ODUzWhcNMjYwNTAxMjA1ODUzWjBeMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHVuYW4xETAPBgNVBAcMCENoYW5nc2hhMRAwDgYDVQQKDAdTYW5nZm9yMQwwCgYDVQQLDANTU0wxDDAKBgNVBAMMA3NkcDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABC8RAVQfeRezPqR6KrcSEwm52r7OIuvP3Bb5hLp8YDal+2wNXS6pFo1hcHLZeT4QAim9+6RBkkHS9+eZkfBUfUijIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQD1VpVTx/scc/E4IbJpehbrH4e6zQ5ci94/rYqlze2GpgIhAOCJSNXKHa3BLia8wM6Ng/J4EyHOC18f5gk9wOaK7WzN\",\"challenge\":\"Q0j2xL+wAlMs5juAn4+Ww4/bw5GHWYU7DqscsqcR3wxQWBm1pOEZp8IL/NiI7axKd9y1MRKEX+n8BandaxcK2PGB8/Juq4ZfPUPR7gtczgkSBw4nVqOrsa8JcOLJM/vC0zCWMRJcYhoNPt1Lj0tBsFDvmSsTIurl5lJzlMWRIUQ=\",\"encryptedChallenge\":\"3903A21DF5DB3815AE356B312F27695978A491A1305F08924BE9AFB14A99945B30CE41C9AA53E59E1A341E7B0ACD041E40634B90C373434E5E4904097235CD81548B696E60FBEFF913BCE45012CF59413BA37D368ADCB34F1FEBF33FA4703A3414D6829884F8B536FE9AFD81E7C99215D13BB9EE7796D186625FFCD25F180CBCB759ACE3BAD86CBBE0F6BABE08C8DB1A9A3268F808C826639908EFCA9F4CF4A848BDBF6AD1AE45BCFB2EEDCDB9D04401\",\"ticket\":\"\",\"mitmSig\":\"cc52b8bd3590d2f8d344c34a5173d39b2430af4547115975b55db87bb66341c6\"},\"udpSpa\":{\"enable\":0,\"encryptedConf\":\"7E9D6C81FC242971A766BF61C18F11369190416B523E760C8E6652A49FF84844717E4414B488CCF1A47BAE146671F47E9A2E306F3DC3386A8E711D06301A927A37E9392AA0295C2110DD5D8AC7C91CC0ECC003F618C6BA345BE08C0FF4E3A104AE47FF18D264E099FE389964AA8B9EF9ADF86C9E2E638D14BA5AEE294CE8DEA47C346D111385EC9012F154B1E58EB0022F8DDF1B14614B309C2E8D9F4EC20E7E89F1F09C075465600D1BB38EC016E26D579B72B108DA4B86E6B881795A3F42A2\",\"sign\":\"764bdc98943048b80ddc8e8eb3988ab68df715d3cae457127a73d0b8fe49edc3\"}},\"traceId\":\"00ca361dd9ae277f\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        if (request.uri().startsWith("/controller/v1/public/events")) {
            return notFound();
        }
        if(request.uri().startsWith("/portal/preset_icon/") && request.uri().endsWith(".png")) {
            try (InputStream in = getClass().getResourceAsStream("/com/github/netguard/sslvpn/atrust/" + FileNameUtil.getName(request.uri()))) {
                if (in == null) {
                    return notFound();
                } else {
                    return fullResponse("image/png", IoUtil.readBytes(in));
                }
            }
        }
        if (request.uri().startsWith("/passport/v1/user/logout")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{},\"traceId\":\"00954697822bd64b\"}", Feature.OrderedField);
            HttpResponse response = handleATrust(request, obj);
            HttpHeaders headers = response.headers();
            headers.add("Set-Cookie", "sid=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=none; secure; httponly");
            return response;
        }
        if (request.uri().startsWith("/passport/v1/public/sangforIdLogout")) {
            JSONObject obj = JSON.parseObject("{\"code\":0,\"message\":\"成功\",\"data\":{},\"traceId\":\"07b4f5e9b73ab2d8\"}", Feature.OrderedField);
            return handleATrust(request, obj);
        }
        return null;
    }

    private HttpResponse handleATrust(HttpRequest request, JSONObject obj) {
        if (log.isDebugEnabled()) {
            log.debug("manifest uri={}, obj={}", request.uri(), obj.toString(SerializerFeature.PrettyFormat));
        }
        HttpResponse response = fullResponse("application/json; charset=utf-8", obj.toJSONString().getBytes(StandardCharsets.UTF_8));
        response.headers().add("X-Server", "aTrust");
        return response;
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
        obj.put("sm2_application", ""); // smxApp
        obj.put("sm2_container", ""); // smxContainer
        obj.put("sm_cert", 0); // smxCertEnable
        obj.put("sm_enc_algo", ""); // smxAlgCipher
        obj.put("sm_enc_algo_id", 0); // smxAlgID
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

    private byte[] handleVpnSecureLogin(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        JSONObject obj = readJSON(buffer);
        if (log.isDebugEnabled()) {
            log.debug("handleVpnSecureLogin: {}", obj);
        }
        JSONObject response = new JSONObject(true);
        response.put("username", "FSXML");
        response.put("access_token", DigestUtil.sha256Hex(msg));
        return buildResponse(tag, response);
    }

    private byte[] handleVpnLogin(int tag, byte[] msg) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(msg);
        JSONObject obj = readJSON(buffer);
        int subAuthType = obj.getIntValue("SubAuthType");
        String username = obj.getString("UserName");
        String password;
        if (subAuthType == QianxinVpn.QX_SUB_AUTH_TYPE) {
            if(username == null || username.isBlank()) {
                username = "FSXML";
            }
            password = "NetGuard";
        } else {
            password = obj.getString("Password");
        }
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
        auth.put("SubAuthType", QianxinVpn.QX_SUB_AUTH_TYPE);
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

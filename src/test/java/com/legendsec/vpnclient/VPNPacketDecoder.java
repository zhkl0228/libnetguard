package com.legendsec.vpnclient;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.handler.http.HttpRequest;
import com.github.netguard.handler.http.HttpResponse;
import com.github.netguard.vpn.AcceptTcpResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.tcp.ConnectRequest;
import org.krakenapps.pcap.decoder.http.impl.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Map;

class VPNPacketDecoder extends PacketDecoder {

    private static final Logger log = LoggerFactory.getLogger(VPNPacketDecoder.class);

    public VPNPacketDecoder() {
        super(new File("target/ssl_vpn.pcap"), true);
//        setUnknownTcpProtocolProcessor(new SacMsgProcessor());
    }

    @Override
    public AcceptTcpResult acceptTcp(ConnectRequest connectRequest) {
        if ("218.19.163.102".equals(connectRequest.serverIp)) {
            if (connectRequest.port == 443 || connectRequest.port == 80) {
                System.out.printf("acceptEasyConnect serverIp=%s, port=%d, hostName=%s, applicationLayerProtocols=%s%n", connectRequest.serverIp, connectRequest.port, connectRequest.hostName, connectRequest.applicationLayerProtocols);
                return AcceptTcpResult.builder(connectRequest.port == 443 ? AllowRule.CONNECT_SSL : AllowRule.CONNECT_TCP).build();
            }
            return connectRequest.disconnect();
        }
        if("vpn.xzit.edu.cn".equals(connectRequest.hostName)) {
            System.out.printf("acceptVpn serverIp=%s, port=%d, hostName=%s, applicationLayerProtocols=%s%n", connectRequest.serverIp, connectRequest.port, connectRequest.hostName, connectRequest.applicationLayerProtocols);
            return AcceptTcpResult.builder(AllowRule.CONNECT_SSL).redirectAddress("211.65.116.119", 4433).build();
        }
        if("wegu.zhongdinggroup.com".equals(connectRequest.hostName)) { // ceshi:1Ad4rDh5cXmy
            try {
                SSLVpnServer server = new SSLVpnServer(connectRequest.hostName, connectRequest.port, 0, connectRequest.applicationLayerProtocols);
                System.out.printf("acceptVpn serverIp=%s, port=%d, hostName=%s, applicationLayerProtocols=%s%n", connectRequest.serverIp, connectRequest.port, connectRequest.hostName, connectRequest.applicationLayerProtocols);
                return AcceptTcpResult.builder(AllowRule.CONNECT_TCP).redirectAddress("127.0.0.1", server.getListenPort()).build();
            } catch (Exception e) {
                log.warn("handle ssl vpn", e);
            }
        }
        if ("vpn.bonc.com.cn".equals(connectRequest.hostName) ||
                "wegu.zhongdinggroup.com".equals(connectRequest.hostName) ||
                "vpn.fdsm.fudan.edu.cn".equals(connectRequest.hostName) ||
                "vpn.gmw.cn".equals(connectRequest.hostName) ||
                "sslvpn.gome.com.cn".equals(connectRequest.hostName) ||
                "stuvpn.gdut.edu.cn".equals(connectRequest.hostName) ||
                "vpn.sues.edu.cn".equals(connectRequest.hostName) ||
                "vpn.gzu.edu.cn".equals(connectRequest.hostName) ||
                "vpn.gxufe.edu.cn".equals(connectRequest.hostName) ||
                "vpn.hnu.edu.cn".equals(connectRequest.hostName) ||
                "vpn.sts.edu.cn".equals(connectRequest.hostName) ||
                "appstore.qianxin.com".equals(connectRequest.hostName)) {
            System.out.printf("acceptVpn serverIp=%s, port=%d, hostName=%s, applicationLayerProtocols=%s%n", connectRequest.serverIp, connectRequest.port, connectRequest.hostName, connectRequest.applicationLayerProtocols);
            return AcceptTcpResult.builder(AllowRule.CONNECT_SSL).build();
        }
        return connectRequest.connectTcpDirect().build();
    }

    @Override
    protected void onRequest(HttpSession session, HttpRequest request) {
        byte[] data = request.getPostData();
        log.info("onRequest {} bytes session={}, application={}, request={}\n{}{}\n", data == null ? 0 : data.length, session, session.getApplication(), request, request.getHeaderString(), parseParameters(request.getRequestUri()));
        final String contentType = request.getHeader("Content-Type");
        if (data != null && contentType != null && contentType.contains("application/json")) {
            String json = new String(data, StandardCharsets.UTF_8);
            JSONObject obj = JSONObject.parseObject(json);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
        }
        if (data != null && request.getRequestUri().startsWith("/por/login_psw.csp")) {
            Map<String, String> params = parseParameters(new String(data, StandardCharsets.UTF_8));
            System.out.println(JSON.toJSONString(params, SerializerFeature.PrettyFormat));
        }
    }

    @Override
    protected void onResponse(HttpSession session, HttpRequest request, HttpResponse response) {
        byte[] data = response.getResponseData();
        log.info("onResponse {} bytes session={}, application={}, requestUri={}, response={}\nResponse code: {} {}\n{}", data == null ? 0 : data.length, session, session.getApplication(), request.getRequestUri(), response, response.getResponseCode(), response.getResponseCodeMsg(), response.getHeaderString());
        final String contentType = response.getHeader("Content-Type");
        if (data != null && contentType != null && contentType.contains("application/json")) {
            String json = new String(data, StandardCharsets.UTF_8);
            JSONObject obj = JSONObject.parseObject(json);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
        }
        if(data != null && contentType != null &&
                (contentType.contains("text/xml") || contentType.contains("application/xml") || contentType.contains("text/html"))) {
            String xml = new String(data, StandardCharsets.UTF_8);
            System.out.println(xml);
        }
    }

}

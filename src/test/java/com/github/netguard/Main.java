package com.github.netguard;

import cn.hutool.core.net.DefaultTrustManager;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.tcp.ConnectRequest;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import com.github.netguard.vpn.tcp.StreamForward;
import com.github.netguard.vpn.tcp.h2.AbstractHttp2Filter;
import com.github.netguard.vpn.tcp.h2.CancelResult;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tls.TlsSignature;
import com.github.netguard.vpn.udp.AcceptRule;
import com.github.netguard.vpn.udp.DNSFilter;
import com.github.netguard.vpn.udp.PacketRequest;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.ResourceLeakDetector;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.conscrypt.OpenSSLProvider;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.http.impl.HttpSession;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED
 * --origin-to-force-quic-on=http3.is:443
 */
public class Main {

    public static void main(String[] args) throws IOException {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.INFO);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.INFO);
        Logger.getLogger(HttpFrameForward.class).setLevel(Level.INFO);
        Logger.getLogger(PacketDecoder.class).setLevel(Level.INFO);
        Logger.getLogger(HttpDecoder.class).setLevel(Level.INFO);
        Logger.getLogger(StreamForward.class).setLevel(Level.INFO);
        Logger.getLogger(HttpFrameForward.class.getPackageName()).setLevel(Level.INFO);
        Logger.getLogger(DNSFilter.class.getPackageName()).setLevel(Level.DEBUG);
        VpnServer vpnServer = new VpnServer(20260);
        vpnServer.preparePreMasterSecretsLogFile();
        vpnServer.enableBroadcast(10);
        vpnServer.enableTransparentProxying();
        vpnServer.setVpnListener(new MyVpnListener());
        vpnServer.start();

        System.out.println("vpn server listen on: " + vpnServer.getPort());
        vpnServer.waitShutdown();
    }

    private static class MyVpnListener extends AbstractHttp2Filter implements VpnListener, Http2Filter, DNSFilter {
        @Override
        public void onConnectClient(Vpn vpn) {
            System.out.println("client: " + vpn.getClientOS() + ", impl=" + vpn.getClass());
            IPacketCapture packetCapture = new MyPacketDecoder();
            vpn.setPacketCapture(packetCapture);
        }
        @Override
        public boolean filterHost(String hostName, boolean h3) {
            if ("weixin.qq.com".equals(hostName) || "http3.is".equals(hostName)) {
                return true;
            } else {
                System.out.printf("NOT filter http%d host=%s%n", h3 ? 3 : 2, hostName);
                return h3;
            }
        }

        @Override
        public CancelResult cancelRequest(HttpRequest request, byte[] requestData, boolean polling) {
            String host = request.headers().get("host");
            if (("weixin.qq.com".equals(host) || "http3.is".equals(host)) && "/".equals(request.uri())) {
                HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                HttpHeaders headers = response.headers();
                headers.set("content-type", "text/plain; charset=utf-8");
                headers.set("cache-control", "no-cache, must-revalidate");
                return CancelResult.fake(response, ("FAKE_HTML: " + new Date()).getBytes());
            }
            return super.cancelRequest(request, requestData, polling);
        }

        @Override
        protected byte[] filterRequestInternal(HttpRequest request, HttpHeaders headers, byte[] requestData) {
            Inspector.inspect(requestData, "filterRequest=" + request);
            return requestData;
        }

        @Override
        protected byte[] filterResponseInternal(HttpRequest request, byte[] requestData, HttpResponse response, byte[] responseData) {
            Inspector.inspect(responseData, "filterResponse=" + response);
            if (response.headers().get(HttpHeaderNames.CONTENT_TYPE).contains("application/json")) {
                try {
                    JSONObject obj = JSONObject.parseObject(new String(responseData, StandardCharsets.UTF_8), Feature.OrderedField);
                    if (obj != null) {
                        obj.put("netguardFilter", getClass().getName());
                        obj.put("filterDate", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                        return obj.toString(SerializerFeature.PrettyFormat).getBytes(StandardCharsets.UTF_8);
                    }
                } catch(Exception e) {
                    e.printStackTrace(System.out);
                }
            }
            return responseData;
        }

        @Override
        protected byte[] filterPollingResponseInternal(HttpRequest request, HttpResponse response, byte[] responseData) {
            return responseData;
        }

        @Override
        public Message cancelDnsQuery(Message dnsQuery) {
            List<Record> list = dnsQuery.getSection(0);
            if (list.size() == 1) {
                Record record = list.get(0);
                if (record.getName().toString().startsWith("qq.com")) {
                    try {
                        Message dnsResponse = new Message(dnsQuery.getHeader().getID());
                        Header header = dnsResponse.getHeader();
                        header.setFlag(Flags.QR);
                        header.setFlag(Flags.RD);
                        header.setFlag(Flags.RA);
                        dnsResponse.addRecord(new ARecord(new Name("qq.com."), DClass.IN, 3600, InetAddress.getByName("192.168.31.88")), 1);
                        return dnsResponse;
                    } catch (Exception e) {
                        throw new IllegalStateException("cancelDnsQuery", e);
                    }
                }
            }
            return null;
        }

        @Override
        public Message filterDnsResponse(Message dnsQuery, Message dnsResponse) {
            List<Record> list = dnsQuery.getSection(0);
            if (list.size() == 1) {
                Record record = list.get(0);
                if (record.getName().toString().startsWith("baidu.com")) {
                    try {
                        dnsResponse.addRecord(new ARecord(new Name("baidu.com."), DClass.IN, 3600, InetAddress.getByName("192.168.31.88")), 1);
                    } catch (Exception e) {
                        throw new IllegalStateException("filterDnsResponse", e);
                    }
                }
            }
            return dnsResponse;
        }

        private class MyPacketDecoder extends PacketDecoder {
            MyPacketDecoder() {
                try {
                    File pcapFile = new File("target/vpn.pcap");
                    FileUtils.deleteQuietly(pcapFile);
                    setOutputPcapFile(pcapFile);
                } catch (IOException e) {
                    throw new IllegalStateException("setOutputPcapFile", e);
                }
            }

            @Override
            protected void onResponse(HttpSession session, com.github.netguard.handler.http.HttpRequest request, com.github.netguard.handler.http.HttpResponse response) {
                if ("application/json".equals(response.getContentType())) {
                    try {
                        JSONObject obj = JSONObject.parseObject(new String(response.getResponseData(), StandardCharsets.UTF_8));
                        System.out.println(obj.toString(SerializerFeature.PrettyFormat));
                    } catch(Exception ignored) {}
                }
                super.onResponse(session, request, response);
            }

            @Override
            public Http2Filter getH2Filter() {
                return MyVpnListener.this;
            }

            @Override
            public DNSFilter getDNSFilter() {
                return MyVpnListener.this;
            }

            private SSLContext createConscryptContext() {
                try {
                    SSLContext context = SSLContext.getInstance("TLSv1.3", "Conscrypt");
                    context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
                    return context;
                } catch (NoSuchAlgorithmException | KeyManagementException | NoSuchProviderException e) {
                    throw new IllegalStateException(e);
                }
            }
            @Override
            public AcceptResult acceptTcp(ConnectRequest connectRequest) {
                TlsSignature tlsSignature = connectRequest.tlsSignature;
                if (tlsSignature != null) {
                    System.out.printf("acceptTcp request=%s, ja3_hash=%s, ja3n_hash=%s, ja4=%s, peetprint_hash=%s, ja3_text=\"%s\", ja3n_text=\"%s\"%n", connectRequest,
                            DigestUtil.md5Hex(tlsSignature.getJa3Text()),
                            DigestUtil.md5Hex(tlsSignature.getJa3nText()),
                            tlsSignature.getJa4Text(),
                            DigestUtil.md5Hex(tlsSignature.getPeetPrintText()),
                            tlsSignature.getJa3Text(),
                            tlsSignature.getJa3nText());
                }
                if ("weixin.qq.com".equals(connectRequest.hostName) || "tls.browserleaks.com".equals(connectRequest.hostName)) {
                    return AcceptResult.builder(AllowRule.FILTER_H2)
                            .configClientSSLContext(createConscryptContext())
                            .build();
                }
                if (connectRequest.isSSL()) {
                    return AcceptResult.builder(connectRequest.hostName.contains("google") ? AllowRule.CONNECT_TCP : AllowRule.CONNECT_SSL)
                            .configClientSSLContext(createConscryptContext())
                            .build();
                }
                Application[] applications = connectRequest.queryApplications();
                System.out.printf("acceptTcp request=%s, applications=%s, httpRequest=%s%n", connectRequest, Arrays.toString(applications), connectRequest.httpRequest);
                return super.acceptTcp(connectRequest);
            }
            @Override
            public AcceptRule acceptUdp(PacketRequest packetRequest) {
                if (packetRequest.dnsQuery != null) {
                    return AcceptRule.Forward;
                }
                TlsSignature tlsSignature = packetRequest.tlsSignature;
                if (tlsSignature != null) {
                    System.out.printf("acceptUdp request=%s, ja3_hash=%s, ja3n_hash=%s, ja4=%s, peetprint_hash=%s, ja3_text=\"%s\", ja3n_text=\"%s\"%n", packetRequest,
                            DigestUtil.md5Hex(tlsSignature.getJa3Text()),
                            DigestUtil.md5Hex(tlsSignature.getJa3nText()),
                            tlsSignature.getJa4Text(),
                            DigestUtil.md5Hex(tlsSignature.getPeetPrintText()),
                            tlsSignature.getJa3Text(),
                            tlsSignature.getJa3nText());
                }
                return AcceptRule.FILTER_H3;
            }
        }
    }

    static {
        /*
         * https://github.com/google/conscrypt
         */
        Security.addProvider(new OpenSSLProvider());
    }

}
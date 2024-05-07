package com.github.netguard;

import cn.hutool.core.net.DefaultTrustManager;
import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.ssl.ConnectRequest;
import com.github.netguard.vpn.ssl.SSLProxyV2;
import com.github.netguard.vpn.ssl.StreamForward;
import com.github.netguard.vpn.ssl.h2.AbstractHttp2Filter;
import com.github.netguard.vpn.ssl.h2.CancelResult;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.Application;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.ResourceLeakDetector;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.wildfly.openssl.OpenSSLProvider;
import org.wildfly.openssl.SSL;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

/**
 * --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED
 */
public class Main {

    public static void main(String[] args) throws IOException {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.INFO);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.INFO);
        Logger.getLogger(PacketDecoder.class).setLevel(Level.DEBUG);
        Logger.getLogger(HttpDecoder.class).setLevel(Level.INFO);
        Logger.getLogger(HttpFrameForward.class).setLevel(Level.INFO);
        Logger.getLogger(StreamForward.class).setLevel(Level.INFO);
        Logger.getLogger("edu.baylor.cs.csi5321.spdy.frames").setLevel(Level.INFO);
        VpnServer vpnServer = new VpnServer(20260);
        vpnServer.preparePreMasterSecretsLogFile();
        vpnServer.enableBroadcast(10);
        vpnServer.enableTransparentProxying();
        vpnServer.setVpnListener(new MyVpnListener());
        vpnServer.start();

        System.out.println("vpn server listen on: " + vpnServer.getPort());
        vpnServer.waitShutdown();
    }

    private static class MyVpnListener extends AbstractHttp2Filter implements VpnListener, Http2Filter {
        @Override
        public void onConnectClient(Vpn vpn) {
            System.out.println("client: " + vpn.getClientOS() + ", impl=" + vpn.getClass());
            IPacketCapture packetCapture = new MyPacketDecoder();
            vpn.setPacketCapture(packetCapture);
        }
        @Override
        public boolean filterHost(String hostName) {
            if (hostName.endsWith("weixin.qq.com")) {
                return true;
            } else {
                System.out.println("NOT filter http2 host=" + hostName);
                return false;
            }
        }

        @Override
        public CancelResult cancelRequest(HttpRequest request, byte[] requestData, boolean polling) {
            String host = request.headers().get("host");
            if ("weixin.qq.com".equals(host) && "/".equals(request.uri())) {
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
            return responseData;
        }

        @Override
        protected byte[] filterPollingResponseInternal(HttpRequest request, HttpResponse response, byte[] responseData) {
            return responseData;
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
            public Http2Filter getH2Filter() {
                return MyVpnListener.this;
            }
            private SSLContext createWeiXinSSLContext() {
                try {
                    SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
                    context.init(new KeyManager[0], new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
                    return context;
                } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
                    throw new IllegalStateException(e);
                }
            }
            private SSLContext createSSLContext() {
                try {
                    SSLContext context = SSLContext.getInstance("openssl.TLS");
                    context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
                    return context;
                } catch (NoSuchAlgorithmException | KeyManagementException e) {
                    throw new IllegalStateException(e);
                }
            }
            @Override
            public AcceptResult acceptTcp(ConnectRequest connectRequest) {
                if ("weixin.qq.com".equals(connectRequest.hostName)) {
                    return AcceptResult.builder(AllowRule.FILTER_H2)
                            .configClientSSLContext(createWeiXinSSLContext())
                            .build();
                }
                if (connectRequest.isSSL()) {
                    return AcceptResult.builder(AllowRule.CONNECT_SSL)
                            .configClientSSLContext(createSSLContext())
                            .build();
                }
                Application[] applications = connectRequest.queryApplications();
                System.out.printf("acceptTcp request=%s, applications=%s, httpRequest=%s%n", connectRequest, Arrays.toString(applications), connectRequest.httpRequest);
                return super.acceptTcp(connectRequest);
            }
        }
    }

    static {
        Security.addProvider(new BouncyCastleJsseProvider());

        /*
         * https://github.com/wildfly-security/wildfly-openssl-natives
         */
        System.setProperty(SSL.ORG_WILDFLY_LIBWFSSL_PATH, new File(FileUtils.getUserDirectory(),
                "git/wildfly-openssl-natives/macosx-aarch64/target/classes/macosx-aarch64/libwfssl.dylib").getAbsolutePath());
        System.setProperty(SSL.ORG_WILDFLY_OPENSSL_PATH, "/opt/local/lib");
        Security.addProvider(new OpenSSLProvider());
    }

}
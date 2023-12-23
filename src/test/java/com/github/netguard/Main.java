package com.github.netguard;

import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.Vpn;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.ssl.ConnectRequest;
import com.github.netguard.vpn.ssl.SSLProxyV2;
import com.github.netguard.vpn.ssl.h2.AbstractHttp2Filter;
import com.github.netguard.vpn.ssl.h2.CancelResult;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.twitter.http2.HttpFrameForward;
import eu.faircode.netguard.ServiceSinkhole;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.ResourceLeakDetector;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.http.HttpDecoder;

import java.io.IOException;
import java.util.Date;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);
        Logger.getLogger(ServiceSinkhole.class).setLevel(Level.INFO);
        Logger.getLogger(SSLProxyV2.class).setLevel(Level.INFO);
        Logger.getLogger(PacketDecoder.class).setLevel(Level.DEBUG);
        Logger.getLogger(HttpDecoder.class).setLevel(Level.DEBUG);
        Logger.getLogger(HttpFrameForward.class).setLevel(Level.INFO);
        Logger.getLogger("edu.baylor.cs.csi5321.spdy.frames").setLevel(Level.INFO);
        VpnServer vpnServer = new VpnServer();
        vpnServer.enableBroadcast(10);
        vpnServer.enableTransparentProxying();
        vpnServer.setVpnListener(new MyVpnListener());
        vpnServer.start();

        System.out.println("vpn server listen on: " + vpnServer.getPort());
        Scanner scanner = new Scanner(System.in);
        String cmd;
        while ((cmd = scanner.nextLine()) != null) {
            if ("q".equals(cmd) || "exit".equals(cmd)) {
                break;
            }
        }
        vpnServer.shutdown();
    }

    private static class MyVpnListener extends AbstractHttp2Filter implements VpnListener, Http2Filter {
        @Override
        public void onConnectClient(Vpn vpn) {
            IPacketCapture packetCapture = new PacketDecoder() {
                @Override
                public Http2Filter getH2Filter() {
                    return MyVpnListener.this;
                }

                @Override
                public AcceptResult acceptTcp(ConnectRequest connectRequest) {
                    if ("weixin.qq.com".equals(connectRequest.hostName)) {
                        return AcceptResult.builder(AllowRule.FILTER_H2).build();
                    }
                    return super.acceptTcp(connectRequest);
                }
            };
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
    }

}
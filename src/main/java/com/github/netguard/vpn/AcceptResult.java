package com.github.netguard.vpn;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class AcceptResult {

    public static class AcceptResultBuilder {
        private final AllowRule rule;
        AcceptResultBuilder(AllowRule rule) {
            this.rule = rule;
        }
        private Proxy proxy = Proxy.NO_PROXY;
        public AcceptResultBuilder enableSocksProxy(String socksHost, int socksPort) {
            this.proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(socksHost, socksPort));
            return this;
        }
        private String redirectAddress;
        private int redirectPort;
        public AcceptResultBuilder redirectAddress(String ip, int port) {
            this.redirectAddress = ip;
            this.redirectPort = port;
            return this;
        }
        private SSLContext sslContext;
        public AcceptResultBuilder configClientSSLContext(SSLContext context) {
            this.sslContext = context;
            return this;
        }
        public AcceptResult build() {
            return build(null);
        }
        public AcceptResult build(String redirectHost) {
            return new AcceptResult(rule, proxy, redirectAddress, redirectPort, redirectHost, sslContext);
        }
    }

    public static AcceptResult disableConnect() {
        return AcceptResult.builder(AllowRule.DISCONNECT).build();
    }

    public static AcceptResultBuilder builder(AllowRule rule) {
        return new AcceptResultBuilder(rule);
    }

    private final AllowRule rule;
    private final Proxy socketProxy;
    private final String redirectAddress;
    private final int redirectPort;
    private final String redirectHost;
    private final SSLContext context;

    private AcceptResult(AllowRule rule, Proxy socketProxy, String redirectAddress, int redirectPort, String redirectHost,
                         SSLContext context) {
        this.rule = rule;
        this.socketProxy = socketProxy;
        this.redirectAddress = redirectAddress;
        this.redirectPort = redirectPort;
        this.redirectHost = redirectHost;
        this.context = context;
    }

    public AllowRule getRule() {
        return rule;
    }

    public Proxy getSocketProxy() {
        return socketProxy;
    }

    public String getRedirectAddress() {
        return redirectAddress;
    }

    public int getRedirectPort() {
        return redirectPort;
    }

    public String getRedirectHost() {
        return redirectHost;
    }

    public static SSLContext newSSLContext(AcceptResult result) {
        if (result != null && result.context != null) {
            return result.context;
        } else {
            try {
                SSLContext context = SSLContext.getInstance("TLSv1.2");
                context.init(new KeyManager[0], new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
                return context;
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new IllegalStateException("newSSLContext", e);
            }
        }
    }

}

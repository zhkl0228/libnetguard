package com.github.netguard.vpn;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class AcceptTcpResult {

    public static class AcceptResultBuilder {
        private final AllowRule rule;
        AcceptResultBuilder(AllowRule rule) {
            this.rule = rule;
        }
        private Proxy proxy = Proxy.NO_PROXY;
        public AcceptResultBuilder enableSocksProxy(String socksHost, int socksPort) {
            return enableSocksProxyV5(socksHost, socksPort, null);
        }
        public AcceptResultBuilder enableSocksProxyV5(String socksHost, int socksPort, String remoteHost) {
            return enableSocksProxyV5(new InetSocketAddress(socksHost, socksPort), remoteHost);
        }
        public AcceptResultBuilder enableSocksProxyV5(InetSocketAddress address, String remoteHost) {
            return enableSocksProxyV5(new Proxy(Proxy.Type.SOCKS, address), remoteHost);
        }
        public AcceptResultBuilder enableSocksProxyV5(Proxy proxy, String remoteHost) {
            if (proxy.type() == Proxy.Type.HTTP) {
                throw new IllegalArgumentException("HTTP proxy type not supported");
            }
            this.proxy = proxy;
            return setRedirectHost(remoteHost);
        }
        private String redirectAddress;
        private int redirectPort;
        @SuppressWarnings("unused")
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
        private String redirectHost;
        public AcceptResultBuilder setRedirectHost(String redirectHost) {
            this.redirectHost = redirectHost;
            return this;
        }
        public AcceptTcpResult build() {
            return build(null);
        }
        public AcceptTcpResult build(String redirectHost) {
            return new AcceptTcpResult(rule, proxy, redirectAddress, redirectPort, redirectHost == null ? this.redirectHost : redirectHost, sslContext);
        }
    }

    @SuppressWarnings("unused")
    public static AcceptTcpResult disableConnect() {
        return AcceptTcpResult.builder(AllowRule.DISCONNECT).build();
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

    private AcceptTcpResult(AllowRule rule, Proxy socketProxy, String redirectAddress, int redirectPort, String redirectHost,
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

    public static SSLContext newSSLContext(AcceptTcpResult result) {
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

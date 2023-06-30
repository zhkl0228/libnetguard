package com.github.netguard.vpn;

import java.net.InetSocketAddress;
import java.net.Proxy;

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
        public AcceptResult build() {
            return new AcceptResult(rule, proxy, redirectAddress, redirectPort);
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

    private AcceptResult(AllowRule rule, Proxy socketProxy, String redirectAddress, int redirectPort) {
        this.rule = rule;
        this.socketProxy = socketProxy;
        this.redirectAddress = redirectAddress;
        this.redirectPort = redirectPort;
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
}

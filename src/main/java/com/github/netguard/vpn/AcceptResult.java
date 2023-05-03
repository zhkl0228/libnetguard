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
        public AcceptResultBuilder redirectAddress(String ip) {
            this.redirectAddress = ip;
            return this;
        }
        public AcceptResult build() {
            return new AcceptResult(rule, proxy, redirectAddress);
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

    private AcceptResult(AllowRule rule, Proxy socketProxy, String redirectAddress) {
        this.rule = rule;
        this.socketProxy = socketProxy;
        this.redirectAddress = redirectAddress;
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
}

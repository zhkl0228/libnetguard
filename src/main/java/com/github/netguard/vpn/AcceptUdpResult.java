package com.github.netguard.vpn;

import com.github.netguard.vpn.udp.AcceptRule;
import com.github.netguard.vpn.udp.ProxyHandler;

import java.net.InetSocketAddress;

public class AcceptUdpResult {

    public static AcceptUdpResult rule(AcceptRule acceptRule) {
        return new AcceptUdpResult(acceptRule, null);
    }

    public final AcceptRule acceptRule;
    public InetSocketAddress udpProxy;

    private AcceptUdpResult(AcceptRule acceptRule, InetSocketAddress udpProxy) {
        this.acceptRule = acceptRule;
        this.udpProxy = udpProxy;
    }

    public AcceptUdpResult setUdpProxy(InetSocketAddress udpProxy) {
        this.udpProxy = udpProxy;
        return this;
    }

    public ProxyHandler proxyHandler;

    public AcceptUdpResult setProxyHandler(ProxyHandler proxyHandler) {
        this.proxyHandler = proxyHandler;
        return this;
    }

}

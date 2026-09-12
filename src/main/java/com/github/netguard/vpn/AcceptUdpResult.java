package com.github.netguard.vpn;

import com.github.netguard.vpn.udp.AcceptRule;
import com.github.netguard.vpn.udp.ProxyHandler;

public class AcceptUdpResult {

    public static AcceptUdpResult rule(AcceptRule acceptRule) {
        return new AcceptUdpResult(acceptRule);
    }

    public final AcceptRule acceptRule;

    private AcceptUdpResult(AcceptRule acceptRule) {
        this.acceptRule = acceptRule;
    }

    public ProxyHandler proxyHandler;

    public AcceptUdpResult setProxyHandler(ProxyHandler proxyHandler) {
        this.proxyHandler = proxyHandler;
        return this;
    }

}

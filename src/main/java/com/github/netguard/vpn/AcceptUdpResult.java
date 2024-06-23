package com.github.netguard.vpn;

import com.github.netguard.vpn.udp.AcceptRule;

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

    public void setUdpProxy(InetSocketAddress udpProxy) {
        this.udpProxy = udpProxy;
    }

}

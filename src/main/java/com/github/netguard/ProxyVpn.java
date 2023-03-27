package com.github.netguard;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;

import java.util.List;

public abstract class ProxyVpn implements Runnable, InspectorVpn {

    protected final List<ProxyVpn> clients;

    protected ProxyVpn(List<ProxyVpn> clients) {
        this.clients = clients;
    }

    protected abstract void stop();

    protected IPacketCapture packetCapture;

    @Override
    public final void setPacketCapture(IPacketCapture packetCapture) {
        this.packetCapture = packetCapture;
    }

    @Override
    public final IPacketCapture getPacketCapture() {
        return packetCapture;
    }

}

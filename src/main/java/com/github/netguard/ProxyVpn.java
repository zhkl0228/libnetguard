package com.github.netguard;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.ssl.RootCert;
import com.github.netguard.vpn.ssl.SSLProxyV2;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;

import java.util.List;

public abstract class ProxyVpn implements Runnable, InspectorVpn {

    protected final List<ProxyVpn> clients;

    protected final RootCert rootCert;

    protected ProxyVpn(List<ProxyVpn> clients, RootCert rootCert) {
        this.clients = clients;
        this.rootCert = rootCert;
    }

    @Override
    public boolean isTransparentProxying() {
        return false;
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

    protected final Allowed redirect(Packet packet) {
        int timeout = 10000; // default 10 seconds;
        return SSLProxyV2.create(this, rootCert, packet, timeout);
    }

}

package com.github.netguard;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.PortRedirector;
import com.github.netguard.vpn.ssl.RootCert;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.List;

public abstract class ProxyVpn implements Runnable, InspectorVpn {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected final List<ProxyVpn> clients;

    protected final RootCert rootCert;

    protected ProxyVpn(List<ProxyVpn> clients) {
        this.clients = clients;
        this.rootCert = RootCert.load();
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

    protected int[] sslPorts;

    @Override
    public final void enableMitm(int... sslPorts) {
        this.sslPorts = sslPorts;
    }

    protected PortRedirector portRedirector;

    @Override
    public void setPortRedirector(PortRedirector portRedirector) {
        this.portRedirector = portRedirector;
    }
}

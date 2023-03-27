package com.github.netguard;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.ServiceSinkhole;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

public abstract class ProxyVpn implements Runnable, InspectorVpn {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected final List<ProxyVpn> clients;

    protected final X509Certificate rootCert;
    protected final PrivateKey privateKey;

    protected ProxyVpn(List<ProxyVpn> clients) {
        this.clients = clients;

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            String alias = "tcpcap-ssl-proxying";
            try (InputStream inputStream = ServiceSinkhole.class.getResourceAsStream("/tcpcap-ssl-proxying.p12")) {
                keyStore.load(inputStream, "tcpcap".toCharArray());
            }
            rootCert = (X509Certificate) keyStore.getCertificate(alias);
            privateKey = (PrivateKey) keyStore.getKey(alias, null);
        } catch (Exception e) {
            throw new IllegalStateException("init ServiceSinkhole", e);
        }
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

}

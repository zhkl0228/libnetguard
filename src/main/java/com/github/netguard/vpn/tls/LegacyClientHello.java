package com.github.netguard.vpn.tls;

import java.util.Collections;
import java.util.List;
import java.util.Map;

class LegacyClientHello implements ClientHello {

    private final int clientVersion;
    private final List<Integer> cipherSuites;
    private final Map<Integer, byte[]> extensionTypes;
    private final List<Integer> ec;
    private final List<Integer> ecpf;
    private final List<Integer> signatureAlgorithms;
    private final String hostName;
    private final List<String> applicationLayerProtocols;

    LegacyClientHello(int clientVersion, List<Integer> cipherSuites, Map<Integer, byte[]> extensionTypes, List<Integer> ec, List<Integer> ecpf, List<Integer> signatureAlgorithms, String hostName, List<String> applicationLayerProtocols) {
        this.clientVersion = clientVersion;
        this.cipherSuites = Collections.unmodifiableList(cipherSuites);
        this.extensionTypes = Collections.unmodifiableMap(extensionTypes);
        this.ec = Collections.unmodifiableList(ec);
        this.ecpf = Collections.unmodifiableList(ecpf);
        this.signatureAlgorithms = Collections.unmodifiableList(signatureAlgorithms);
        this.hostName = hostName;
        this.applicationLayerProtocols = Collections.unmodifiableList(applicationLayerProtocols);
    }

    @Override
    public int getClientVersion() {
        return clientVersion;
    }

    @Override
    public String getHostName() {
        return hostName;
    }

    @Override
    public List<Integer> getCipherSuites() {
        return cipherSuites;
    }

    @Override
    public Map<Integer, byte[]> getExtensionTypes() {
        return extensionTypes;
    }

    @Override
    public List<String> getApplicationLayerProtocols() {
        return applicationLayerProtocols;
    }

    @Override
    public List<Integer> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    @Override
    public List<Integer> getEllipticCurves() {
        return ec;
    }

    @Override
    public List<Integer> getEllipticCurvePointFormats() {
        return ecpf;
    }

    @Override
    public char getJa4Prefix() {
        return 't';
    }
}

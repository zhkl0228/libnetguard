package com.github.netguard.vpn.ssl;

import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.List;

class ClientHelloRecord {
    public final byte[] readData;
    public final String hostName;
    public final List<String> applicationLayerProtocols;

    ClientHelloRecord(ByteArrayOutputStream baos) {
        this(baos, null, Collections.<String>emptyList());
    }

    ClientHelloRecord(ByteArrayOutputStream baos, String hostName, List<String> applicationLayerProtocols) {
        this.readData = baos.toByteArray();
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
    }

    @Override
    public String toString() {
        return "ClientHelloRecord{" +
                "hostName='" + hostName + '\'' +
                "applicationLayerProtocols='" + applicationLayerProtocols + '\'' +
                '}';
    }
}

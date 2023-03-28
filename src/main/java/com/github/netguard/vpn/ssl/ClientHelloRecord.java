package com.github.netguard.vpn.ssl;

import java.io.ByteArrayOutputStream;

class ClientHelloRecord {
    public final byte[] readData;
    public final String hostName;

    ClientHelloRecord(ByteArrayOutputStream baos) {
        this(baos, null);
    }

    ClientHelloRecord(ByteArrayOutputStream baos, String hostName) {
        this.readData = baos.toByteArray();
        this.hostName = hostName;
    }

    @Override
    public String toString() {
        return "ClientHelloRecord{" +
                "hostName='" + hostName + '\'' +
                '}';
    }
}

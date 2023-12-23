package com.github.netguard.vpn.ssl;

import eu.faircode.netguard.Packet;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ClientHelloRecord {

    private static final int PROLOGUE_MAX_LENGTH = 128;

    static ClientHelloRecord prologue(ByteArrayOutputStream baos, DataInputStream dataInput) throws IOException {
        int available = dataInput.available();
        int count = PROLOGUE_MAX_LENGTH - baos.size();
        if (available > 0 && count > 0) {
            byte[] buf = new byte[Math.min(count, available)];
            dataInput.readFully(buf);
            baos.write(buf);
        }
        return new ClientHelloRecord(baos);
    }

    ConnectRequest newConnectRequest(Packet packet) {
        return new ConnectRequest(packet.daddr, packet.dport, this.hostName, this.applicationLayerProtocols, this.prologue);
    }

    public final byte[] prologue;
    public final String hostName;
    public final List<String> applicationLayerProtocols;

    private ClientHelloRecord(ByteArrayOutputStream baos) {
        this(baos, null, new ArrayList<>());
    }

    ClientHelloRecord(ByteArrayOutputStream baos, String hostName, List<String> applicationLayerProtocols) {
        this.prologue = baos.toByteArray();
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
    }

    @Override
    public String toString() {
        return "ClientHelloRecord{" +
                "hostName='" + hostName + '\'' +
                ", applicationLayerProtocols='" + applicationLayerProtocols + '\'' +
                '}';
    }
}

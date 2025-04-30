package com.github.netguard.handler;

import org.krakenapps.pcap.packet.PacketHeader;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.ChainBuffer;

import java.io.File;
import java.io.IOException;

public class PcapFileOutputStream extends org.krakenapps.pcap.file.PcapFileOutputStream {

    private final static int CONST_RAW_IP = 101;

    public PcapFileOutputStream(File file) throws IOException {
        super(file, CONST_RAW_IP);
    }

    private static PcapPacket createPcapPacket(byte[] packet) {
        long currentTimeMillis = System.currentTimeMillis();
        int tsSec = (int) (currentTimeMillis / 1000);
        int tsUsec = (int) (currentTimeMillis % 1000);
        PacketHeader header = new PacketHeader(tsSec, tsUsec, packet.length, packet.length);
        return new PcapPacket(header, new ChainBuffer(packet)).setDatalink(CONST_RAW_IP);
    }

    public final void writePacket(byte[] data) throws IOException {
        write(createPcapPacket(data));
    }

}

package com.github.netguard.vpn.udp.quic.kwik;

import net.luminis.quic.log.BaseLogger;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class PrintStreamLogger extends BaseLogger {

    private final PrintStream out;

    PrintStreamLogger(PrintStream out) {
        this.out = out;
    }

    @Override
    protected void log(String message) {
        synchronized (this) {
            out.println(message);
        }
    }

    @Override
    protected void log(String message, Throwable error) {
        synchronized (this) {
            out.println(message);
            error.printStackTrace(out);
        }

    }

    @Override
    protected void logWithHexDump(String message, byte[] data, int length) {
        synchronized (this) {
            out.println(message);
            out.println(byteToHexBlock(data, length));
        }
    }

    @Override
    protected void logWithHexDump(String message, ByteBuffer data, int offset, int length) {
        synchronized (this) {
            out.println(message);
            out.println(byteToHexBlock(data, offset, length));
        }
    }

}

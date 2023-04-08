package com.github.netguard.vpn.ssl;

import java.nio.ByteBuffer;

/**
 * @author zhkl0228
 *
 */
class HandshakeParser implements Handshake {

    private static int readThreeByteInt(ByteBuffer buffer) {
        int ch1 = buffer.get() & 0xff;
        int ch2 = buffer.get() & 0xff;
        int ch3 = buffer.get() & 0xff;
        return ((ch1 << 16) + (ch2 << 8) + ch3);
    }

    static Handshake parseHandshake(ByteBuffer buffer) {
        byte type = buffer.get();
        int length = readThreeByteInt(buffer);
        byte[] data = new byte[length];
        buffer.get(data);
        HandshakeType handshakeType = HandshakeType.parseType(type);
        return new HandshakeParser(handshakeType, data);
    }

    private final HandshakeType type;
    private final ByteBuffer buffer;

    private HandshakeParser(HandshakeType type, byte[] data) {
        super();
        this.type = type;
        this.buffer = ByteBuffer.wrap(data);
    }

    @Override
    public HandshakeType getType() {
        return type;
    }

    @Override
    public ByteBuffer getBuffer() {
        return buffer;
    }
}

package com.github.netguard.vpn.tcp;

/**
 * @author zhkl0228
 *
 */
enum ContentType {

    ChangeCipherSpec(0x14),

    Alert(0x15),

    Handshake(0x16),

    ApplicationData(0x17),

    UNKNOWN(-1);

    private final byte value;

    ContentType(int value) {
        this.value = (byte) value;
    }

    public byte getValue() {
        return value;
    }

}

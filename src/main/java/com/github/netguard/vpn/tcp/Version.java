package com.github.netguard.vpn.tcp;

/**
 * @author zhkl0228
 *
 */
enum Version {

    SSLv3_0(0x300),

    TLSv1_0(0x301),

    TLSv1_1(0x302),

    TLSv1_2(0x303),

    TLSv1_3(0x304),

    // Dummy protocol version value for invalid SSLSession
    NONE(-1);

    private final short value;

    Version(int value) {
        this.value = (short) value;
    }

    public short getValue() {
        return value;
    }

}

package com.github.netguard.vpn.tcp;

/**
 * @author zhkl0228
 *
 */
enum HandshakeType {

    HelloRequest(0x0),

    ClientHello(0x1),

    ServerHello(0x2),

    HelloVerifyRequest(0x3),

    NewSessionTicket(0x4),

    EndOfEarlyData(0x5),

    EncryptedExtensions(0x8),

    Certificate(0xb),

    ServerKeyExchange(0xc),

    CertificateRequest(0xd),

    ServerHelloDone(0xe),

    CertificateVerify(0xf),

    ClientKeyExchange(0x10),

    Finished(0x14),

    CertificateStatus(0x16),

    KeyUpdate(0x18),

    NextProtocol(0x43);

    private final byte value;

    HandshakeType(int value) {
        this.value = (byte) value;
    }

    static HandshakeType parseType(byte value) {
        for(HandshakeType ht : HandshakeType.values()) {
            if(value == ht.value) {
                return ht;
            }
        }
        return null;
    }

}

package com.github.netguard.vpn.ssl;

import java.nio.ByteBuffer;

/**
 * @author zhkl0228
 *
 */
interface Handshake {

    HandshakeType getType();

    ByteBuffer getBuffer();

}

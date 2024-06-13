package com.github.netguard.vpn.tcp;

import java.nio.ByteBuffer;

/**
 * @author zhkl0228
 *
 */
interface Handshake {

    HandshakeType getType();

    ByteBuffer getBuffer();

}

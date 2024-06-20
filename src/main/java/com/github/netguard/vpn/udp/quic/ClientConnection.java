package com.github.netguard.vpn.udp.quic;

import com.github.netguard.vpn.tcp.h2.Http2Session;

import java.io.Closeable;
import java.io.IOException;

public interface ClientConnection extends Closeable {

    HandshakeResult handshake(Http2Session session) throws IOException;

}

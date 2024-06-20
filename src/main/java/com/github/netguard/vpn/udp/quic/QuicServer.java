package com.github.netguard.vpn.udp.quic;

import java.io.Closeable;
import java.net.InetSocketAddress;

public interface QuicServer extends Closeable {

    InetSocketAddress getForwardAddress();

}

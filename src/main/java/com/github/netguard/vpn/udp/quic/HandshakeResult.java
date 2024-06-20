package com.github.netguard.vpn.udp.quic;

import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.h2.Http2Filter;

public interface HandshakeResult {

    QuicServer startServer(InspectorVpn vpn, Http2Filter http2Filter) throws Exception;

}

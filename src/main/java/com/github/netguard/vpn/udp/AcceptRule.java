package com.github.netguard.vpn.udp;

public enum AcceptRule {

    /**
     * forward udp traffic
     */
    Forward,

    /**
     * discard udp packet
     */
    Discard,

    /**
     * quic in the middle
     */
    QUIC_MITM

}

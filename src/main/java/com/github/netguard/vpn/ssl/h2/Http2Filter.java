package com.github.netguard.vpn.ssl.h2;

public interface Http2Filter {

    boolean acceptHost(String hostName);

}

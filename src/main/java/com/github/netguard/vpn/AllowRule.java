package com.github.netguard.vpn;

public enum AllowRule {

    DISCONNECT, // 不允许连接
    CONNECT_SSL, // 连接为 SSL
    FILTER_H2, // 对 Http2 流量进行劫持
    CONNECT_TCP // 连接为 TCP

}

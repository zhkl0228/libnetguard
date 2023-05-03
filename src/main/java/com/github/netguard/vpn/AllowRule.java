package com.github.netguard.vpn;

public enum AllowRule {

    DISCONNECT, // 不允许连接
    CONNECT_SSL, // 连接为 SSL，并进行中间人抓包
    FILTER_H2, // 连接为 SSL，并对 Http2 流量进行劫持
    CONNECT_TCP // 连接为 TCP

}

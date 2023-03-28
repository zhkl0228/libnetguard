package com.github.netguard.vpn.ssl;

enum HandshakeStatus {

    handshaking, // 正在握手
    failed1, // 握手失败一次
    failed2, // 握手失败两次
    success, // 握手成功,
    not_tls // 不是 TLS 协议

}

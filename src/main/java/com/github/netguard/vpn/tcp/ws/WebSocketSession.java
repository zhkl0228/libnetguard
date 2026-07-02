package com.github.netguard.vpn.tcp.ws;

import java.net.InetSocketAddress;

/**
 * 一条被 MITM 的 WebSocket 连接的会话信息。
 */
public class WebSocketSession {

    private final InetSocketAddress client;
    private final InetSocketAddress server;
    private final String hostName;

    // 由 server 端 101 响应的 Sec-WebSocket-Extensions 解析得到
    volatile boolean permessageDeflate;
    volatile boolean serverNoContextTakeover;
    volatile boolean clientNoContextTakeover;
    volatile boolean established;

    public WebSocketSession(InetSocketAddress client, InetSocketAddress server, String hostName) {
        this.client = client;
        this.server = server;
        this.hostName = hostName;
    }

    public InetSocketAddress getClient() {
        return client;
    }

    public InetSocketAddress getServer() {
        return server;
    }

    public String getHostName() {
        return hostName;
    }

    public boolean isPermessageDeflate() {
        return permessageDeflate;
    }

    public boolean isEstablished() {
        return established;
    }

    /** 供跨包(HTTP/2 RFC 8441 路径)标记握手完成。 */
    public void markEstablished() {
        this.established = true;
    }

    @Override
    public String toString() {
        return "WebSocketSession{" + client + " => " + server + " (" + hostName + "), deflate=" + permessageDeflate + '}';
    }
}

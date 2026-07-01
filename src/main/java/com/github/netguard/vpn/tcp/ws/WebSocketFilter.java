package com.github.netguard.vpn.tcp.ws;

/**
 * WebSocket 帧过滤/观测/注入钩子,与 {@link com.github.netguard.vpn.tcp.h2.Http2Filter} 对称。
 * 仅当连接被 MITM 解密(AllowRule.CONNECT_SSL/FILTER_H2)且 {@link #filterHost(String)} 返回 true 时启用。
 */
public interface WebSocketFilter {

    /**
     * 是否对该主机的 WebSocket 连接启用过滤。
     */
    boolean filterHost(String hostName);

    /**
     * WebSocket 握手完成、进入帧模式时回调一次,交出注入句柄。
     */
    void onConnected(WebSocketSession session, WebSocketInjector injector);

    /**
     * 每个解码后的帧回调。
     *
     * @param fromServer true 表示 server-&gt;client(数据帧),false 表示 client-&gt;server
     * @param frame      已解掩码、已解压的帧
     * @return 要实际转发的帧:返回入参本身=原样透传(字节保真);返回新帧=替换(重新编码);返回 null=丢弃
     */
    WebSocketFrame onFrame(WebSocketSession session, boolean fromServer, WebSocketFrame frame);

    /**
     * 连接关闭回调。
     */
    void onClosed(WebSocketSession session);
}

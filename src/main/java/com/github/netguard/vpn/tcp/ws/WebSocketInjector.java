package com.github.netguard.vpn.tcp.ws;

/**
 * 向被 MITM 的 WebSocket 连接主动注入帧。由 netguard 提供实现。
 * 注入帧一律以未压缩(RSV1=0)发送,避免打乱 permessage-deflate 滑窗;
 * client-&gt;server 方向自动加掩码,server-&gt;client 方向不加掩码。
 */
public interface WebSocketInjector {

    /** 注入到服务器方向(伪装成客户端,加掩码)。 */
    void sendToServer(WebSocketFrame frame);

    /** 注入到客户端方向(伪装成服务器,不加掩码)。 */
    void sendToClient(WebSocketFrame frame);

    void sendTextToServer(String text);

    void sendBinaryToServer(byte[] data);

    void sendTextToClient(String text);

    void sendBinaryToClient(byte[] data);

    /** 连接是否已完成握手、可注入。 */
    boolean isReady();
}

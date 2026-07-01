package com.github.netguard.vpn.tcp.ws;

import java.nio.charset.StandardCharsets;

/**
 * 一个 WebSocket 帧(已解掩码、已解压)的值对象,供 {@link WebSocketFilter} 观测/替换,以及注入。
 * 不持有 Netty ByteBuf,无引用计数生命周期负担。
 */
public class WebSocketFrame {

    public static final int OPCODE_CONTINUATION = 0x0;
    public static final int OPCODE_TEXT = 0x1;
    public static final int OPCODE_BINARY = 0x2;
    public static final int OPCODE_CLOSE = 0x8;
    public static final int OPCODE_PING = 0x9;
    public static final int OPCODE_PONG = 0xA;

    private final int opcode;
    private final boolean fin;
    private final boolean rsv1; // permessage-deflate 压缩标志(观测用;payload 已是解压后的明文)
    private final byte[] payload;

    public WebSocketFrame(int opcode, boolean fin, boolean rsv1, byte[] payload) {
        this.opcode = opcode;
        this.fin = fin;
        this.rsv1 = rsv1;
        this.payload = payload == null ? new byte[0] : payload;
    }

    public static WebSocketFrame text(String text) {
        return new WebSocketFrame(OPCODE_TEXT, true, false, text.getBytes(StandardCharsets.UTF_8));
    }

    public static WebSocketFrame binary(byte[] data) {
        return new WebSocketFrame(OPCODE_BINARY, true, false, data);
    }

    public int getOpcode() {
        return opcode;
    }

    public boolean isFin() {
        return fin;
    }

    public boolean isRsv1() {
        return rsv1;
    }

    public byte[] getPayload() {
        return payload;
    }

    public boolean isText() {
        return opcode == OPCODE_TEXT;
    }

    public boolean isBinary() {
        return opcode == OPCODE_BINARY;
    }

    public boolean isControl() {
        return opcode == OPCODE_CLOSE || opcode == OPCODE_PING || opcode == OPCODE_PONG;
    }

    public String text() {
        return new String(payload, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "WebSocketFrame{opcode=" + opcode + ", fin=" + fin + ", rsv1=" + rsv1 + ", len=" + payload.length + '}';
    }
}

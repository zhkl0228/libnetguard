package com.twitter.http2;

import com.github.netguard.vpn.tcp.ws.WebSocketCodec;
import com.github.netguard.vpn.tcp.ws.WebSocketSession;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;

import java.io.ByteArrayOutputStream;

class Stream {

    final HttpHeadersFrame httpHeadersFrame;
    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    Stream(HttpHeadersFrame httpHeadersFrame) {
        this.httpHeadersFrame = httpHeadersFrame;
    }

    boolean longPolling;
    boolean headerWritten;

    // ==== WebSocket over HTTP/2 (RFC 8441) ====
    boolean webSocket;
    WebSocketSession webSocketSession; // 请求侧(inbound)持有,响应侧从 peer 读取
    WebSocketCodec codec;              // 本方向帧解码器(解压 inflater 状态)
    ByteArrayOutputStream wsMsgBuf;    // 分片消息累积(仅观测)
    boolean wsMsgRsv1;
    int wsMsgOpcode;

    /** 请求侧:扩展 CONNECT 且 :protocol=websocket(RFC 8441)。 */
    final boolean detectWebSocketRequest() {
        HttpHeaders headers = httpHeadersFrame.headers();
        String method = headers.get(":method");
        String protocol = headers.get(":protocol");
        return HttpMethod.CONNECT.name().equalsIgnoreCase(method) &&
                "websocket".equalsIgnoreCase(protocol);
    }

    /** 响应侧:对端流已识别为 WebSocket,且 :status=200 表示握手成功。 */
    final boolean detectWebSocketResponse() {
        return httpHeadersFrame.headers().getInt(":status", -1) == 200;
    }

    final boolean detectLongPolling() {
        HttpHeaders headers = httpHeadersFrame.headers();
        return !headers.contains(HttpHeaderNames.CONTENT_LENGTH) &&
                !headers.contains(HttpHeaderNames.TRANSFER_ENCODING) &&
                !headers.contains(HttpHeaderNames.CONTENT_RANGE);
    }

    @Override
    public String toString() {
        return "Stream{" +
                "httpHeadersFrame=" + httpHeadersFrame +
                ", longPolling=" + longPolling +
                '}';
    }
}

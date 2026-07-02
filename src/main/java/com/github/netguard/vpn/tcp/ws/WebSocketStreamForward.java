package com.github.netguard.vpn.tcp.ws;

import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.ForwardHandler;
import com.github.netguard.vpn.tcp.StreamForward;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

/**
 * WebSocket 帧转发(MITM,HTTP/1.1 经典 Upgrade)。策略:
 * - 每帧原始字节按位透传(保真,免掩码/压缩重编码的坑);
 * - 同时解码一份副本(解掩码 + permessage-deflate 解压)喂 {@link WebSocketFilter} 观测;
 * - filter 对"单帧完整消息"可替换/丢弃;分片消息仅观测(先透传)。
 * inbound(server=true):client-&gt;server;outbound(server=false):server-&gt;client。
 * 帧编解码逻辑委托 {@link WebSocketCodec}(与 HTTP/2 RFC 8441 路径共用)。
 */
public class WebSocketStreamForward extends StreamForward {

    private static final Logger log = LoggerFactory.getLogger(WebSocketStreamForward.class);

    private final WebSocketFilter filter;
    private final WebSocketSession session;
    private final WebSocketCodec codec;
    private final Object writeLock = new Object();

    public WebSocketStreamForward(InputStream inputStream, OutputStream outputStream, boolean server,
                                  InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress,
                                  CountDownLatch countDownLatch, Socket socket, InspectorVpn vpn, String hostName,
                                  WebSocketSession session, WebSocketFilter filter, Packet packet, ForwardHandler forwardHandler) {
        super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, vpn, hostName, true, packet, forwardHandler);
        this.session = session;
        this.filter = filter;
        this.codec = new WebSocketCodec(session, server);
    }

    /** 在该方向的输出流上写入编码后的帧(线程安全)。inbound 写向服务器,outbound 写向客户端。 */
    void writeFrame(WebSocketFrame frame, boolean mask) throws IOException {
        byte[] encoded = WebSocketCodec.encode(frame.getOpcode(), frame.isFin(), frame.getPayload(), mask);
        synchronized (writeLock) {
            outputStream.write(encoded);
            outputStream.flush();
        }
    }

    private void writeRaw(byte[] raw) throws IOException {
        synchronized (writeLock) {
            outputStream.write(raw);
            outputStream.flush();
        }
    }

    @Override
    protected boolean forward(byte[] buf) throws IOException {
        try {
            socket.setSoTimeout(0); // WS 长连接,阻塞读
        } catch (Exception ignored) {
        }
        DataInputStream in = new DataInputStream(inputStream);
        relayHandshake(in);
        session.established = true;

        // 分片消息累积缓冲(仅用于观测)
        ByteArrayOutputStream msgBuf = null;
        boolean msgRsv1 = false;
        int msgOpcode = 0;

        while (true) {
            WebSocketCodec.Frame rf;
            try {
                rf = WebSocketCodec.readFrame(in);
            } catch (EOFException e) {
                break;
            }
            if (rf == null) {
                break;
            }
            boolean singleComplete = rf.fin && rf.opcode != WebSocketFrame.OPCODE_CONTINUATION;

            if (filter == null) {
                writeRaw(rf.raw);
                continue;
            }

            if (singleComplete) {
                byte[] plain = codec.decode(rf.unmaskedRaw(), rf.rsv1);
                WebSocketFrame wf = new WebSocketFrame(rf.opcode, true, rf.rsv1, plain);
                WebSocketFrame out;
                try {
                    out = filter.onFrame(session, !server, wf);
                } catch (Throwable t) {
                    log.warn("onFrame error", t);
                    out = wf;
                }
                if (out == null) {
                    continue; // 丢弃
                }
                if (out == wf) {
                    writeRaw(rf.raw); // 原样透传
                } else {
                    writeFrame(out, server); // 替换(未压缩重编码;inbound 加掩码)
                }
            } else {
                // 分片:先透传,再累积观测
                writeRaw(rf.raw);
                if (rf.opcode != WebSocketFrame.OPCODE_CONTINUATION) {
                    msgBuf = new ByteArrayOutputStream();
                    msgRsv1 = rf.rsv1;
                    msgOpcode = rf.opcode;
                }
                if (msgBuf != null) {
                    msgBuf.write(rf.unmaskedRaw());
                    if (rf.fin) {
                        byte[] plain = codec.decode(msgBuf.toByteArray(), msgRsv1);
                        try {
                            filter.onFrame(session, !server, new WebSocketFrame(msgOpcode, true, msgRsv1, plain));
                        } catch (Throwable t) {
                            log.warn("onFrame(fragmented) error", t);
                        }
                        msgBuf = null;
                    }
                }
            }
        }
        if (filter != null) {
            try {
                filter.onClosed(session);
            } catch (Throwable ignored) {
            }
        }
        return true;
    }

    // ==== 握手 ====
    private void relayHandshake(DataInputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream(256);
        int c;
        int match = 0; // 匹配 \r\n\r\n
        while ((c = in.read()) >= 0) {
            head.write(c);
            if ((match == 0 && c == '\r') || (match == 2 && c == '\r')) {
                match++;
            } else if ((match == 1 && c == '\n') || (match == 3 && c == '\n')) {
                match++;
            } else {
                match = 0;
            }
            if (match == 4) {
                break;
            }
        }
        byte[] headerBytes = head.toByteArray();
        writeRaw(headerBytes);
        if (!server) {
            parseExtensions(new String(headerBytes, StandardCharsets.ISO_8859_1));
        }
    }

    private void parseExtensions(String responseHead) {
        String lower = responseHead.toLowerCase();
        int idx = lower.indexOf("sec-websocket-extensions:");
        if (idx < 0) {
            return;
        }
        int end = lower.indexOf("\r\n", idx);
        String value = end < 0 ? lower.substring(idx + "sec-websocket-extensions:".length())
                : lower.substring(idx + "sec-websocket-extensions:".length(), end);
        WebSocketCodec.parseExtensions(value, session);
    }

    // ==== 注入器 ====
    public static WebSocketInjector newInjector(final WebSocketStreamForward inbound, final WebSocketStreamForward outbound, final WebSocketSession session) {
        return new WebSocketInjector() {
            @Override
            public void sendToServer(WebSocketFrame frame) {
                try {
                    inbound.writeFrame(frame, true);
                } catch (IOException e) {
                    log.warn("sendToServer failed", e);
                }
            }
            @Override
            public void sendToClient(WebSocketFrame frame) {
                try {
                    outbound.writeFrame(frame, false);
                } catch (IOException e) {
                    log.warn("sendToClient failed", e);
                }
            }
            @Override
            public void sendTextToServer(String text) {
                sendToServer(WebSocketFrame.text(text));
            }
            @Override
            public void sendBinaryToServer(byte[] data) {
                sendToServer(WebSocketFrame.binary(data));
            }
            @Override
            public void sendTextToClient(String text) {
                sendToClient(WebSocketFrame.text(text));
            }
            @Override
            public void sendBinaryToClient(byte[] data) {
                sendToClient(WebSocketFrame.binary(data));
            }
            @Override
            public boolean isReady() {
                return session.established;
            }
        };
    }
}

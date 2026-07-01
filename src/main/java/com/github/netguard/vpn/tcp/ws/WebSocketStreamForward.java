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
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * WebSocket 帧转发(MITM)。策略:
 * - 每帧原始字节按位透传(保真,免掩码/压缩重编码的坑);
 * - 同时解码一份副本(解掩码 + permessage-deflate 解压)喂 {@link WebSocketFilter} 观测;
 * - filter 对"单帧完整消息"可替换/丢弃;分片消息仅观测(先透传)。
 * inbound(server=true):client-&gt;server;outbound(server=false):server-&gt;client。
 */
public class WebSocketStreamForward extends StreamForward {

    private static final Logger log = LoggerFactory.getLogger(WebSocketStreamForward.class);

    private final WebSocketFilter filter;
    private final WebSocketSession session;
    private final Object writeLock = new Object();

    private WebSocketStreamForward peer;
    private Inflater inflater; // 仅解码方向按需创建(context takeover 时跨消息复用)

    public WebSocketStreamForward(InputStream inputStream, OutputStream outputStream, boolean server,
                                  InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress,
                                  CountDownLatch countDownLatch, Socket socket, InspectorVpn vpn, String hostName,
                                  WebSocketSession session, WebSocketFilter filter, Packet packet, ForwardHandler forwardHandler) {
        super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, vpn, hostName, true, packet, forwardHandler);
        this.session = session;
        this.filter = filter;
    }

    public WebSocketStreamForward setPeer(WebSocketStreamForward peer) {
        this.peer = peer;
        peer.peer = this;
        return this;
    }

    /** 在该方向的输出流上写入编码后的帧(线程安全)。inbound 写向服务器,outbound 写向客户端。 */
    void writeFrame(WebSocketFrame frame, boolean mask) throws IOException {
        byte[] encoded = encode(frame.getOpcode(), frame.isFin(), frame.getPayload(), mask);
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

    boolean isServerBound() {
        return server; // inbound => 写向真实服务器
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
            RawFrame rf;
            try {
                rf = readFrame(in);
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
                byte[] plain = decode(rf, rf.rsv1);
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
                        byte[] plain = decodeBytes(msgBuf.toByteArray(), msgRsv1);
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
        try {
            filter.onClosed(session);
        } catch (Throwable ignored) {
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
        String line = end < 0 ? lower.substring(idx) : lower.substring(idx, end);
        if (line.contains("permessage-deflate")) {
            session.permessageDeflate = true;
            session.serverNoContextTakeover = line.contains("server_no_context_takeover");
            session.clientNoContextTakeover = line.contains("client_no_context_takeover");
        }
    }

    // ==== 帧读取 ====
    private static class RawFrame {
        boolean fin;
        boolean rsv1;
        int opcode;
        boolean masked;
        byte[] maskKey;
        byte[] payload; // 原始(可能被掩码)
        byte[] raw;     // 完整原始帧字节(透传用)

        byte[] unmaskedRaw() {
            if (!masked) {
                return payload;
            }
            byte[] p = payload.clone();
            for (int i = 0; i < p.length; i++) {
                p[i] ^= maskKey[i & 3];
            }
            return p;
        }
    }

    private RawFrame readFrame(DataInputStream in) throws IOException {
        int b0 = in.read();
        if (b0 < 0) {
            return null;
        }
        int b1 = in.readUnsignedByte();
        RawFrame f = new RawFrame();
        f.fin = (b0 & 0x80) != 0;
        f.rsv1 = (b0 & 0x40) != 0;
        f.opcode = b0 & 0x0F;
        f.masked = (b1 & 0x80) != 0;
        long len = b1 & 0x7F;
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        raw.write(b0);
        raw.write(b1);
        if (len == 126) {
            int hi = in.readUnsignedByte(), lo = in.readUnsignedByte();
            len = (hi << 8) | lo;
            raw.write(hi);
            raw.write(lo);
        } else if (len == 127) {
            byte[] ext = new byte[8];
            in.readFully(ext);
            raw.write(ext);
            len = 0;
            for (byte b : ext) {
                len = (len << 8) | (b & 0xFF);
            }
        }
        if (f.masked) {
            f.maskKey = new byte[4];
            in.readFully(f.maskKey);
            raw.write(f.maskKey);
        }
        if (len > Integer.MAX_VALUE - 16) {
            throw new IOException("frame too large: " + len);
        }
        f.payload = new byte[(int) len];
        in.readFully(f.payload);
        raw.write(f.payload);
        f.raw = raw.toByteArray();
        return f;
    }

    // ==== 解码(解掩码 + 解压) ====
    private byte[] decode(RawFrame f, boolean rsv1) throws IOException {
        return decodeBytes(f.unmaskedRaw(), rsv1);
    }

    private byte[] decodeBytes(byte[] unmasked, boolean rsv1) throws IOException {
        if (!rsv1 || !session.permessageDeflate) {
            return unmasked;
        }
        if (inflater == null) {
            inflater = new Inflater(true);
        }
        byte[] input = new byte[unmasked.length + 4];
        System.arraycopy(unmasked, 0, input, 0, unmasked.length);
        input[unmasked.length] = 0x00;
        input[unmasked.length + 1] = 0x00;
        input[unmasked.length + 2] = (byte) 0xFF;
        input[unmasked.length + 3] = (byte) 0xFF;
        inflater.setInput(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, unmasked.length * 4));
        byte[] tmp = new byte[8192];
        try {
            while (!inflater.needsInput() && !inflater.finished()) {
                int n = inflater.inflate(tmp);
                if (n == 0) {
                    break;
                }
                out.write(tmp, 0, n);
            }
        } catch (DataFormatException e) {
            throw new IOException("inflate", e);
        }
        boolean noContext = server ? session.clientNoContextTakeover : session.serverNoContextTakeover;
        if (noContext) {
            inflater.reset();
        }
        return out.toByteArray();
    }

    // ==== 编码(未压缩;mask 由方向决定) ====
    static byte[] encode(int opcode, boolean fin, byte[] payload, boolean mask) {
        if (payload == null) {
            payload = new byte[0];
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream(payload.length + 14);
        o.write((fin ? 0x80 : 0) | (opcode & 0x0F));
        int len = payload.length;
        int maskBit = mask ? 0x80 : 0;
        if (len < 126) {
            o.write(maskBit | len);
        } else if (len < 65536) {
            o.write(maskBit | 126);
            o.write((len >>> 8) & 0xFF);
            o.write(len & 0xFF);
        } else {
            o.write(maskBit | 127);
            for (int i = 7; i >= 0; i--) {
                o.write((int) ((((long) len) >>> (i * 8)) & 0xFF));
            }
        }
        if (mask) {
            byte[] key = new byte[4];
            ThreadLocalRandom.current().nextBytes(key);
            o.write(key, 0, 4);
            for (int i = 0; i < payload.length; i++) {
                o.write(payload[i] ^ key[i & 3]);
            }
        } else {
            o.write(payload, 0, payload.length);
        }
        return o.toByteArray();
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

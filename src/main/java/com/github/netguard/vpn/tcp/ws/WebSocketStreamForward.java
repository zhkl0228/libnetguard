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
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

/**
 * WebSocket frame forwarding for a MITM'd HTTP/1.1 connection to a host the {@link WebSocketFilter} asked for.
 * <ul>
 * <li>The connection becomes a WebSocket only if its first request is an upgrade and the server answers 101.
 * Anything else (plain HTTP, a rejected upgrade, a protocol that is not HTTP) is relayed byte for byte.</li>
 * <li>Each frame's original bytes are passed through unchanged, so masking and compression are never re-encoded.</li>
 * <li>A decoded copy (unmasked, permessage-deflate inflated) goes to the {@link WebSocketFilter}, which may replace
 * or drop a single-frame message; fragmented messages are passed through first and only observed.</li>
 * </ul>
 * inbound (server=true): client-&gt;server; outbound (server=false): server-&gt;client.
 * Frame encoding and decoding is in {@link WebSocketCodec}, shared with the HTTP/2 (RFC 8441) path.
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
        writeRaw(raw, raw.length);
    }

    private void writeRaw(byte[] raw, int length) throws IOException {
        synchronized (writeLock) {
            outputStream.write(raw, 0, length);
            outputStream.flush();
        }
    }

    private WebSocketInjector injector;

    /**
     * Set on the server-to-client forward only. It is the side that sees the handshake response, so once it has
     * relayed a 101 it marks the session established and hands this injector to {@link WebSocketFilter#onConnected}.
     */
    public void setInjector(WebSocketInjector injector) {
        this.injector = injector;
    }

    private static final byte[] GET = "GET ".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] SWITCHING_PROTOCOLS = "HTTP/1.1 101 ".getBytes(StandardCharsets.ISO_8859_1);

    @Override
    protected boolean forward(byte[] buf) throws IOException {
        try {
            socket.setSoTimeout(0); // WS 长连接,阻塞读
        } catch (Exception ignored) {
        }
        DataInputStream in = new DataInputStream(inputStream);
        if (server) {
            forwardFromClient(in, buf);
        } else {
            forwardFromServer(in, buf);
        }
        return true;
    }

    /**
     * Client to server. Only a connection whose first request is a WebSocket upgrade can become a WebSocket;
     * anything else is relayed byte for byte and reported to the packet capture, like any other MITM connection.
     */
    private void forwardFromClient(DataInputStream in, byte[] buf) throws IOException {
        byte[] head = readPrefix(in, GET);
        if (Arrays.equals(head, GET)) {
            head = readHead(in, head);
        }
        if (!isUpgradeRequest(head)) {
            relayRaw(in, head, buf, true);
            return;
        }
        session.upgradeRequested = true;
        writeRaw(head);
        try {
            session.handshakeDone.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException ioe = new InterruptedIOException("Waiting for the WebSocket handshake response: session=" + session);
            ioe.initCause(e);
            throw ioe;
        }
        if (!session.established) {
            // Rejected upgrade. The packet capture never saw this request, so it sees none of the connection.
            relayRaw(in, new byte[0], buf, false);
            return;
        }
        try {
            relayFrames(in);
        } finally {
            session.endStream(filter);
        }
    }

    /**
     * Server to client. A 101 answering the upgrade request makes this a WebSocket; any other first response
     * means the connection stays plain HTTP and is relayed byte for byte.
     */
    private void forwardFromServer(DataInputStream in, byte[] buf) throws IOException {
        byte[] head;
        try {
            head = readPrefix(in, SWITCHING_PROTOCOLS);
            if (session.upgradeRequested && Arrays.equals(head, SWITCHING_PROTOCOLS)) {
                head = readHead(in, head);
                writeRaw(head);
                parseExtensions(new String(head, StandardCharsets.ISO_8859_1));
                // Before the client-to-server side is released, so no client frame reaches the filter ahead of onConnected
                session.connect(filter, injector);
            }
        } finally {
            session.handshakeDone.countDown();
        }
        if (!session.established) {
            relayRaw(in, head, buf, !session.upgradeRequested);
            return;
        }
        try {
            relayFrames(in);
        } finally {
            session.endStream(filter);
        }
    }

    /**
     * Relays the rest of the connection unchanged.
     *
     * @param head bytes already read from <code>in</code>, sent first
     * @param notify also report the bytes to the packet capture, as {@link StreamForward} does
     */
    private void relayRaw(DataInputStream in, byte[] head, byte[] buf, boolean notify) throws IOException {
        if (head.length > 0) {
            if (notify) {
                notifyForward(head, head.length);
            }
            writeRaw(head);
        }
        int read;
        while ((read = in.read(buf)) != -1) {
            if (notify) {
                read = notifyForward(buf, read);
            }
            writeRaw(buf, read);
        }
    }

    private void relayFrames(DataInputStream in) throws IOException {
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
    }

    // ==== 握手 ====
    /**
     * Reads bytes while they match <code>expected</code>. Stops at the first byte that differs (included in the
     * result) or at EOF, so traffic that is not HTTP is never held back waiting for more bytes.
     */
    private static byte[] readPrefix(DataInputStream in, byte[] expected) throws IOException {
        ByteArrayOutputStream read = new ByteArrayOutputStream(expected.length);
        for (byte b : expected) {
            int c = in.read();
            if (c < 0) {
                break;
            }
            read.write(c);
            if (c != (b & 0xff)) {
                break;
            }
        }
        return read.toByteArray();
    }

    /**
     * Reads the rest of an HTTP head, up to and including the blank line, or up to EOF.
     *
     * @param start what was already read of the head; contains no line break
     */
    private static byte[] readHead(DataInputStream in, byte[] start) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream(256);
        head.write(start);
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
        return head.toByteArray();
    }

    /**
     * An opening handshake carries "Upgrade: websocket" (RFC 6455 4.1). Header names and this token are
     * case-insensitive.
     */
    private static boolean isUpgradeRequest(byte[] head) {
        for (String line : new String(head, StandardCharsets.ISO_8859_1).split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && "upgrade".equalsIgnoreCase(line.substring(0, colon).trim()) &&
                    "websocket".equalsIgnoreCase(line.substring(colon + 1).trim())) {
                return true;
            }
        }
        return false;
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

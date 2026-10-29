package com.twitter.http2;

import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.ForwardHandler;
import com.github.netguard.vpn.tcp.StreamForward;
import com.github.netguard.vpn.tcp.h2.*;
import com.github.netguard.vpn.tcp.h2.HttpHeaderBlockDecoder;
import com.github.netguard.vpn.tcp.h2.HttpHeaderBlockEncoder;
import com.github.netguard.vpn.tcp.ws.WebSocketCodec;
import com.github.netguard.vpn.tcp.ws.WebSocketFilter;
import com.github.netguard.vpn.tcp.ws.WebSocketFrame;
import com.github.netguard.vpn.tcp.ws.WebSocketInjector;
import com.github.netguard.vpn.tcp.ws.WebSocketSession;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameRstStream;
import edu.baylor.cs.csi5321.spdy.frames.H2Util;
import eu.faircode.netguard.Packet;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class HttpFrameForward extends StreamForward implements HttpFrameDecoderDelegate {

    private static final Logger log = LoggerFactory.getLogger(HttpFrameForward.class);

    private final NetGuardFrameDecoder frameDecoder;
    private final HttpFrameEncoder frameEncoder;

    private final HttpHeaderBlockDecoder headerDecoder;
    private final HttpHeaderBlockEncoder headerEncoder;

    private final Http2Session session;
    private final Http2Filter filter;
    private final WebSocketFilter wsFilter;
    private final String sessionKey;

    /** 序列化输出流写入(转发循环刷盘 与 WebSocket 异步注入 竞争同一 outputStream)。 */
    private final Object outputWriteLock = new Object();

    public HttpFrameForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket, InspectorVpn vpn, String hostName,
                            Http2Session session, Packet packet, ForwardHandler forwardHandler) {
        super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, vpn, hostName, true, packet, forwardHandler);
        this.frameDecoder = new NetGuardFrameDecoder(server, this);
        this.frameEncoder = new HttpFrameEncoder();

        headerDecoder = new HttpHeaderBlockDecoder(0x4000, 0x10000);
        headerEncoder = new HttpHeaderBlockEncoder(0x100);

        this.session = session;
        this.filter = packetCapture == null ? null : packetCapture.getH2Filter();
        this.wsFilter = packetCapture == null ? null : packetCapture.getWebSocketFilter();
        this.sessionKey = String.valueOf(session);
    }

    private HttpFrameForward peer;

    public HttpFrameForward setPeer(HttpFrameForward peer) {
        this.peer = peer;
        peer.peer = this;
        return this;
    }

    private boolean canStop;

    /** The thread running {@link #forward(byte[])}; frames written from any other thread take the cross-thread path. */
    private volatile Thread forwardThread;

    @Override
    protected boolean forward(byte[] buf) throws IOException {
        forwardThread = Thread.currentThread();
        DataInputStream dataInput;
        ByteBuf byteBuf = Unpooled.buffer();
        try {
            dataInput = new DataInputStream(inputStream);
            if (server) {
                byte[] preface = new byte[24];
                dataInput.readFully(preface);
                byteBuf.writeBytes(preface);
                frameDecoder.decode(byteBuf);
                outputStream.write(preface);

                if (packetCapture != null) {
                    packetCapture.onSSLProxyTx(clientSocketAddress, serverSocketAddress, preface);
                }
            }
            while (!canStop) {
                int header = dataInput.readInt();
                int length = (header >>> 8) & H2Util.MASK_LENGTH_HEADER;
                byte flags = dataInput.readByte();
                int stream = dataInput.readInt();

                byteBuf.writeInt(header);
                byteBuf.writeByte(flags);
                byteBuf.writeInt(stream);
                if (log.isDebugEnabled()) {
                    int streamId = stream & H2Util.MASK_STREAM_ID_HEADER;
                    log.debug("read frame length server={}, length={}, flags=0x{}, streamId={}", server, length, Integer.toHexString(flags & 0xff), streamId);
                }
                while (length > 0) {
                    int read = dataInput.read(buf, 0, Math.min(length, buf.length));
                    if (read == -1) {
                        throw new EOFException();
                    }
                    byteBuf.writeBytes(buf, 0, read);
                    length -= read;
                }
                byte[] input = null;
                if (log.isDebugEnabled()) {
                    byteBuf.markReaderIndex();
                    input = new byte[byteBuf.readableBytes()];
                    byteBuf.readBytes(input);
                    byteBuf.resetReaderIndex();
                }
                while (byteBuf.isReadable()) {
                    frameDecoder.decode(byteBuf);
                }
                // The decoder copies what it keeps, so reuse the buffer instead of growing it for the whole connection
                byteBuf.clear();
                if (dataInput.available() > 0) {
                    continue;
                }

                if (input != null) {
                    log.debug("forward server={}, inHash={}, input={}", server, DigestUtils.md5Hex(input), Hex.encodeHexString(input));
                    if (log.isTraceEnabled()) {
                        trace(server ? "outbound" : "inbound", input);
                    }
                }
                writeWindowUpdates();
                byte[] output = outputBuffer.toByteArray();
                outputBuffer.reset();
                writeBuffered(output);
            }
            return true;
        } catch (SocketTimeoutException ignored) {
        } catch (UncheckedIOException e) {
            // Socket writes made inside frame callbacks; let doForward treat them like any other socket error
            throw e.getCause();
        } finally {
            byteBuf.release();
            this.peer = null;
        }
        return false;
    }

    @Override
    public void readDataFramePadding(int streamId, boolean endStream, int padding) {
        log.debug("readDataFramePadding server={}, streamId={}, endStream={}, padding={}", server, streamId, endStream, padding);
        throw new UnsupportedOperationException();
    }

    @Override
    public void readDataFrame(int streamId, boolean endStream, boolean endSegment, ByteBuf data) {
        Stream stream = streamMap.get(streamId);
        log.debug("readDataFrame server={}, streamId={}, endStream={}, endSegment={}, longPolling={}, data={}", server, streamId, endStream, endSegment, (stream == null ? null : stream.longPolling), data);
        try {
            onDataRead(streamId, endStream, data.readableBytes());
            if (stream == null) {
                log.warn("readDataFrame not exists stream: {}", streamId);
                return;
            }
            data.readBytes(stream.buffer, data.readableBytes());
            if (stream.webSocket) {
                byte[] chunk = stream.buffer.toByteArray();
                stream.buffer.reset();
                handleWebSocketData(stream, chunk, endStream);
                return;
            }
            if (stream.longPolling) {
                if (server) {
                    handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), endStream, false, streamId, false);
                } else {
                    handlePollingResponse(stream.httpHeadersFrame, stream.buffer.toByteArray(), endStream);
                }
                stream.buffer.reset();
                return;
            }
            if (endStream) {
                streamMap.remove(streamId);
                if (server) {
                    handleRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), streamId);
                } else {
                    handleResponse(stream.httpHeadersFrame, stream.buffer.toByteArray(), false);
                }
                stream.buffer.reset();
            } else {
                log.debug("readDataFrame server={}", server);
                if (server) {
                    if (stream.detectLongPolling()) {
                        stream.longPolling = true;
                        handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), false, true, streamId, !stream.headerWritten);
                        stream.headerWritten = false;
                        stream.buffer.reset();
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("readDataFrame", e);
        } finally {
            data.release();
        }
    }

    // ==== WebSocket over HTTP/2 (RFC 8441):把该流的 DATA 载荷当作 RFC 6455 帧流处理 ====
    private void handleWebSocketData(Stream stream, byte[] chunk, boolean endStream) {
        WebSocketSession wsSession = stream.webSocketSession;
        boolean fromServer = !server; // outbound(server=false) => server->client
        List<WebSocketCodec.Frame> frames;
        try {
            frames = stream.codec.parse(chunk);
        } catch (Exception e) {
            log.warn("webSocket parse failed", e);
            return;
        }
        for (WebSocketCodec.Frame rf : frames) {
            boolean singleComplete = rf.fin && rf.opcode != WebSocketFrame.OPCODE_CONTINUATION;
            if (singleComplete) {
                byte[] plain;
                try {
                    plain = stream.codec.decode(rf.unmaskedRaw(), rf.rsv1);
                } catch (IOException e) {
                    log.warn("webSocket decode failed", e);
                    writeWebSocketData(stream.httpHeadersFrame.getStreamId(), rf.raw);
                    continue;
                }
                WebSocketFrame wf = new WebSocketFrame(rf.opcode, true, rf.rsv1, plain);
                WebSocketFrame out;
                try {
                    out = wsFilter.onFrame(wsSession, fromServer, wf);
                } catch (Throwable t) {
                    log.warn("onFrame error", t);
                    out = wf;
                }
                if (out == null) {
                    continue; // 丢弃
                }
                if (out == wf) {
                    writeWebSocketData(stream.httpHeadersFrame.getStreamId(), rf.raw); // 原样透传
                } else {
                    // 替换:未压缩重编码;client->server(server=true)方向加掩码
                    byte[] encoded = WebSocketCodec.encode(out.getOpcode(), out.isFin(), out.getPayload(), server);
                    writeWebSocketData(stream.httpHeadersFrame.getStreamId(), encoded);
                }
            } else {
                // 分片:先透传,再累积观测
                writeWebSocketData(stream.httpHeadersFrame.getStreamId(), rf.raw);
                if (rf.opcode != WebSocketFrame.OPCODE_CONTINUATION) {
                    stream.wsMsgBuf = new ByteArrayOutputStream();
                    stream.wsMsgRsv1 = rf.rsv1;
                    stream.wsMsgOpcode = rf.opcode;
                }
                if (stream.wsMsgBuf != null) {
                    stream.wsMsgBuf.write(rf.unmaskedRaw(), 0, rf.unmaskedRaw().length);
                    if (rf.fin) {
                        try {
                            byte[] plain = stream.codec.decode(stream.wsMsgBuf.toByteArray(), stream.wsMsgRsv1);
                            wsFilter.onFrame(wsSession, fromServer, new WebSocketFrame(stream.wsMsgOpcode, true, stream.wsMsgRsv1, plain));
                        } catch (Throwable t) {
                            log.warn("onFrame(fragmented) error", t);
                        }
                        stream.wsMsgBuf = null;
                    }
                }
            }
        }
        if (endStream) {
            streamMap.remove(stream.httpHeadersFrame.getStreamId());
            try {
                wsFilter.onClosed(wsSession);
            } catch (Throwable ignored) {
            }
        }
    }

    /** Sends encoded WebSocket frame bytes as h2 DATA on this direction. */
    private void writeWebSocketData(int streamId, byte[] wsBytes) {
        sendData(streamId, wsBytes, false);
    }

    /** Writes and flushes under the lock: the forward loop, the peer thread and filter threads share this outputStream. */
    private void writeLocked(byte[] data) throws IOException {
        synchronized (outputWriteLock) {
            outputStream.write(data);
            outputStream.flush();
        }
    }

    /** Writes under the lock and reports the bytes to the packet capture (Tx or Rx by direction). */
    private void writeOutput(byte[] data) throws IOException {
        writeLocked(data);
        if (packetCapture != null) {
            if (server) {
                packetCapture.onSSLProxyTx(clientSocketAddress, serverSocketAddress, data);
            } else {
                packetCapture.onSSLProxyRx(clientSocketAddress, serverSocketAddress, data);
            }
        }
        if (log.isTraceEnabled()) {
            trace(server ? "outbound_forward" : "inbound_forward", data);
        }
    }

    /** Appends the bytes as hex to this connection's trace file under target/. */
    private void trace(String direction, byte[] data) throws IOException {
        String clientIp = clientSocketAddress.getAddress().getHostAddress();
        int clientPort = clientSocketAddress.getPort();
        String serverIp = serverSocketAddress.getAddress().getHostAddress();
        int serverPort = serverSocketAddress.getPort();
        String date = new SimpleDateFormat("[HH:mm:ss SSS]").format(new Date());
        File file = new File("target/" + String.format("%s:%d_%s:%d_%s.txt", clientIp, clientPort, serverIp, serverPort, direction));
        FileUtils.write(file, date + Hex.encodeHexString(data), StandardCharsets.UTF_8, true);
    }

    /**
     * WebSocket injection: encodes the frame and sends it as h2 DATA on this direction (asynchronously, from a filter
     * thread). It goes through the same flow-control queue as forwarded DATA, so it stays within the receiver's windows.
     */
    private void injectWebSocketFrame(int streamId, WebSocketFrame frame, boolean mask) {
        byte[] payload = WebSocketCodec.encode(frame.getOpcode(), frame.isFin(), frame.getPayload(), mask);
        try {
            sendData(streamId, payload, false);
        } catch (UncheckedIOException e) {
            log.warn("injectWebSocketFrame failed", e);
        }
    }

    /** inbound=写向真实服务器(加掩码);outbound=写向客户端(不加掩码)。 */
    private static WebSocketInjector newWebSocketInjector(final HttpFrameForward inbound, final HttpFrameForward outbound,
                                                          final int streamId, final WebSocketSession session) {
        return new WebSocketInjector() {
            @Override
            public void sendToServer(WebSocketFrame frame) {
                inbound.injectWebSocketFrame(streamId, frame, true);
            }
            @Override
            public void sendToClient(WebSocketFrame frame) {
                outbound.injectWebSocketFrame(streamId, frame, false);
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
                return session.isEstablished();
            }
        };
    }

    private HttpHeadersFrame httpHeadersFrame;

    @Override
    public void readHeadersFrame(int streamId, boolean endStream, boolean endSegment, boolean exclusive, int dependency, int weight) {
        log.debug("readHeadersFrame server={}, streamId={}, endStream={}, endSegment={}, exclusive={}, dependency={}, weight={}", server, streamId, endStream, endSegment, exclusive, dependency, weight);

        if (httpHeadersFrame != null) {
            throw new IllegalStateException("readHeadersFrame=" + httpHeadersFrame);
        }
        httpHeadersFrame = new NetGuardHttpHeadersFrame(streamId);
        httpHeadersFrame.setLast(endStream);
        httpHeadersFrame.setExclusive(exclusive);
        httpHeadersFrame.setDependency(dependency);
        httpHeadersFrame.setWeight(weight);
    }

    @Override
    public void readHeaderBlock(ByteBuf headerBlockFragment) {
        log.debug("readHeaderBlock server={}, headerBlockFragment={}", server, headerBlockFragment);
        try {
            headerDecoder.decode(headerBlockFragment, httpHeadersFrame);
        } catch (IOException e) {
            throw new IllegalStateException("readHeaderBlock frame=" + httpHeadersFrame, e);
        } finally {
            headerBlockFragment.release();
        }
    }

    private final Map<Integer, Stream> streamMap = new HashMap<>();

    private static final int DEFAULT_CHUNK_SIZE = 0x1000;

    /** Sends HEADERS, then the body as DATA when data is not null (an empty body is a single empty DATA frame). */
    private void writeMessage(HttpHeadersFrame headersFrame, byte[] data, boolean endStreamOnFlush) {
        log.debug("writeMessage server={}, headersFrame={}, endStreamOnFlush={}", server, headersFrame, endStreamOnFlush);
        sendFrames(headersFrame.getStreamId(), headersFrame, data, endStreamOnFlush);
    }

    /** Resets the stream toward this direction's receiver; runs on the peer thread when the filter cancels a request. */
    private void writeCancelStreamFrame(int streamId) {
        ByteBuf frame = frameEncoder.encodeRstStreamFrame(streamId, H2FrameRstStream.ErrorCode.CANCEL.ordinal());
        try {
            ByteArrayOutputStream rstStream = new ByteArrayOutputStream();
            forwardFrameBuf(frame, rstStream);
            synchronized (flowLock) {
                sendStreams.remove(streamId);
                writeDirect(rstStream.toByteArray());
            }
        } finally {
            frame.release();
        }
    }

    private void handlePollingRequest(HttpHeadersFrame headersFrame, byte[] requestData, boolean endStreamOnFlush, boolean newStream, int streamId, boolean writeHeaders) {
        HttpRequest request = filter == null ? null : createHttpRequest(headersFrame, sessionKey, akamai);
        if (filter != null) {
            CancelResult result = filter.cancelRequest(request, requestData == null ? new byte[0] : requestData, true);
            if (result != null) {
                if (result.cancel) {
                    closeRecvStream(streamId);
                    peer.writeCancelStreamFrame(streamId);
                } else {
                    throw new UnsupportedOperationException("response=" + result.response);
                }
                return;
            }
        }
        byte[] data = filter == null ? requestData : filter.filterPollingRequest(new Http2SessionKey(session, headersFrame.getStreamId(), false), request, requestData, newStream);
        if (writeHeaders) {
            writeMessage(headersFrame, data, endStreamOnFlush);
        }
        sendData(headersFrame.getStreamId(), data, endStreamOnFlush);
    }

    private void handlePollingResponse(HttpHeadersFrame headersFrame, byte[] responseData, boolean endStreamOnFlush) {
        byte[] data = filter == null ? responseData : filter.filterPollingResponse(new Http2SessionKey(session, headersFrame.getStreamId(), false),
                createHttpResponse(headersFrame, sessionKey, akamai),
                responseData, endStreamOnFlush);
        sendData(headersFrame.getStreamId(), data, endStreamOnFlush);
    }

    private void handleRequest(HttpHeadersFrame headersFrame, byte[] requestData, int streamId) {
        HttpRequest request = filter == null ? null : createHttpRequest(headersFrame, sessionKey, akamai);
        if (filter != null) {
            CancelResult result = filter.cancelRequest(request, requestData == null ? new byte[0] : requestData, false);
            if (result != null) {
                skipStreamOpen(streamId);
                if (result.cancel) {
                    peer.writeCancelStreamFrame(streamId);
                } else {
                    byte[] responseData = result.responseData;
                    HttpResponse response = result.response;
                    HttpHeadersFrame fakeHeadersFrame = new NetGuardHttpHeadersFrame(streamId);
                    fakeHeadersFrame.setLast(responseData != null && responseData.length == 0);
                    HttpHeaders headers = fakeHeadersFrame.headers();
                    headers.setInt(":status", response.status().code());
                    HttpHeaders fakeHeaders = response.headers();
                    for (Iterator<Map.Entry<String, String>> iterator = fakeHeaders.iteratorAsString(); iterator.hasNext(); ) {
                        Map.Entry<String, String> entry = iterator.next();
                        headers.add(entry.getKey(), entry.getValue());
                    }
                    headers.set("x-netguard-fake-response", sessionKey);
//                    filter.filterRequest(new Http2SessionKey(session, headersFrame.getStreamId(), false), request, headersFrame.headers(), requestData == null ? new byte[0] : requestData);
                    // Runs on this thread but writes through the peer's queue, which keeps it behind the server's SETTINGS
                    peer.handleResponse(fakeHeadersFrame, responseData, true);
                }
                return;
            }
        }
        byte[] body = requestData == null ? new byte[0] : requestData;
        byte[] data = filter == null ? body : filter.filterRequest(new Http2SessionKey(session, headersFrame.getStreamId(), false), request,
                headersFrame.headers(), body);
        if (data == null) {
            throw new IllegalStateException();
        }
        writeMessage(headersFrame, requestData == null && data.length == 0 ? null : data, true);
    }

    private void handleResponse(HttpHeadersFrame headersFrame, byte[] responseData, boolean fakeResponse) {
        byte[] data;
        if (fakeResponse) {
            data = responseData;
        } else {
            byte[] body = responseData == null ? new byte[0] : responseData;
            data = filter == null ? body : filter.filterResponse(new Http2SessionKey(session, headersFrame.getStreamId(), false),
                    createHttpResponse(headersFrame, sessionKey, akamai),
                    headersFrame.headers(), body);
        }
        if (data == null) {
            throw new IllegalStateException();
        }
        HttpHeaders headers = headersFrame.headers();
        headers.setInt("x-http2-stream-id", headersFrame.getStreamId());
        headers.setInt("x-http2-stream-weight", headersFrame.getWeight());
        headers.set("x-netguard-session", sessionKey);
        writeMessage(headersFrame, responseData == null && data.length == 0 ? null : data, true);
    }

    @Override
    public void readHeaderBlockEnd() {
        if (httpHeadersFrame.isTruncated()) {
            throw new UnsupportedOperationException("frame=" + httpHeadersFrame);
        }

        headerDecoder.endHeaderBlock(httpHeadersFrame);
        log.debug("readHeaderBlockEnd server={}, frame={}", server, httpHeadersFrame);

        if (server) {
            akamai.onHttpHeadersFrame(httpHeadersFrame);
        }

        if (httpHeadersFrame.isLast()) {
            Stream stream = streamMap.get(httpHeadersFrame.getStreamId());
            if (stream != null) {
                streamMap.remove(httpHeadersFrame.getStreamId());
                closeRecvStream(httpHeadersFrame.getStreamId());
                stream.httpHeadersFrame.headers().setAll(httpHeadersFrame.headers());
                if (server) {
                    handleRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), httpHeadersFrame.getStreamId());
                } else {
                    handleResponse(stream.httpHeadersFrame, stream.buffer.toByteArray(), false);
                }
                stream.buffer.reset();
            } else {
                if (server) {
                    onClientStream(httpHeadersFrame.getStreamId());
                    handleRequest(httpHeadersFrame, null, httpHeadersFrame.getStreamId());
                } else {
                    handleResponse(httpHeadersFrame, null, false);
                }
            }
        } else {
            Stream stream = new Stream(httpHeadersFrame);
            Stream old = streamMap.put(httpHeadersFrame.getStreamId(), stream);
            if (old != null) {
                log.warn("readHeaderBlockEnd replace exists stream old={}", old);
            } else {
                log.debug("readHeaderBlockEnd server={}, stream={}", server, stream);
            }

            int streamId = httpHeadersFrame.getStreamId();
            openRecvStream(streamId);
            if (server) {
                onClientStream(streamId);
            }
            Stream peerStream = server ? null : peer.streamMap.get(streamId);

            if (wsFilter != null && server && stream.detectWebSocketRequest() && wsFilter.filterHost(hostName)) {
                // WebSocket over HTTP/2(RFC 8441)请求侧:扩展 CONNECT,转发头(不结束流),等待响应
                stream.webSocket = true;
                stream.webSocketSession = new WebSocketSession(clientSocketAddress, serverSocketAddress, hostName);
                stream.codec = new WebSocketCodec(stream.webSocketSession, true);
                writeMessage(stream.httpHeadersFrame, null, false);
                stream.headerWritten = true;
            } else if (wsFilter != null && !server && peerStream != null && peerStream.webSocket && stream.detectWebSocketResponse()) {
                // WebSocket over HTTP/2 响应侧::status=200 握手成功,登记会话并回调 onConnected
                WebSocketSession wsSession = peerStream.webSocketSession;
                stream.webSocket = true;
                stream.webSocketSession = wsSession;
                stream.codec = new WebSocketCodec(wsSession, false);
                WebSocketCodec.parseExtensions(httpHeadersFrame.headers().get("sec-websocket-extensions"), wsSession);
                wsSession.markEstablished();
                writeMessage(stream.httpHeadersFrame, null, false);
                WebSocketInjector injector = newWebSocketInjector(peer, this, streamId, wsSession);
                try {
                    wsFilter.onConnected(wsSession, injector);
                } catch (Throwable t) {
                    log.warn("webSocket onConnected failed", t);
                }
            } else if (!server && peerStream != null && peerStream.longPolling) {
                stream.longPolling = true;
                writeMessage(stream.httpHeadersFrame, null, false);
            } else {
                log.debug("readHeaderBlockEnd server={}, httpHeadersFrame={}, streamMap={}", server, httpHeadersFrame, peer.streamMap);

                if (server) {
                    if (stream.detectLongPolling()) {
                        stream.longPolling = true;
                        writeMessage(stream.httpHeadersFrame, null, false);
                        stream.headerWritten = true;
                        stream.buffer.reset();
                    }
                }
            }
        }
        httpHeadersFrame = null;
    }

    @Override
    public void readPriorityFrame(int streamId, boolean exclusive, int dependency, int weight) {
        log.debug("readPriorityFrame server={}, streamId={}, exclusive={}, dependency={}, weight={}", server, streamId, exclusive, dependency, weight);

        if (server) {
            akamai.onPriorityFrame(streamId, exclusive, dependency, weight);
        }

        ByteBuf frame = frameEncoder.encodePriorityFrame(streamId, exclusive, dependency, weight);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readRstStreamFrame(int streamId, int errorCode) {
        log.debug("readRstStreamFrame server={}, streamId={}, errorCode={}", server, streamId, errorCode);
        // The stream is gone on both connections: drop what is still queued for it and stop acknowledging its DATA
        closeStream(streamId);
        peer.closeStream(streamId);
        if (skipStreamOpen(streamId)) {
            // The server never saw this stream, and RST_STREAM on an idle stream is a connection error (RFC 9113 §5.1)
            log.debug("readRstStreamFrame drop RST_STREAM of a stream never opened toward the server streamId={}", streamId);
        } else {
            ByteBuf frame = frameEncoder.encodeRstStreamFrame(streamId, errorCode);
            try {
                forwardFrameBuf(frame, outputBuffer);
            } finally {
                frame.release();
            }
        }
        Stream stream = streamMap.remove(streamId);
        if (stream != null && stream.webSocket && wsFilter != null) {
            try {
                wsFilter.onClosed(stream.webSocketSession);
            } catch (Throwable ignored) {
            }
        }
    }

    private HttpSettingsFrame httpSettingsFrame;
    private final Akamai akamai = new Akamai();

    @Override
    public void readSettingsFrame(boolean ack) {
        httpSettingsFrame = new NetGuardHttpSettingsFrame();
        httpSettingsFrame.setAck(ack);
        log.debug("readSettingsFrame server={}, ack={}", server, ack);
    }

    @Override
    public void readSetting(int id, int value) {
        log.debug("readSetting server={}, id={}, value={}", server, id, value);
        httpSettingsFrame.setValue(id, value);
    }

    @Override
    public void readSettingsEnd() {
        log.debug("readSettingsEnd server={}, frame={}", server, httpSettingsFrame);

        if (server) {
            akamai.onHttpSettingsFrame(httpSettingsFrame);
        }

        peer.onPeerSettingsEnd(httpSettingsFrame);
        if (!httpSettingsFrame.isAck()) {
            settingsBuffered = true;
        }
        ByteBuf frame = frameEncoder.encodeSettingsFrame(httpSettingsFrame);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
        httpSettingsFrame = null;
    }

    private final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();

    private void forwardFrameBuf(ByteBuf byteBuf, ByteArrayOutputStream outputBuffer) {
        try {
            log.debug("forwardFrameBuf server={}, byteBuf={}", server, byteBuf);
            byteBuf.readBytes(outputBuffer, byteBuf.readableBytes());
        } catch (IOException e) {
            throw new IllegalStateException("forwardFrameBuf", e);
        }
    }

    /** Frames other threads wrote before this direction forwarded its first SETTINGS; guarded by outputWriteLock. */
    private final List<byte[]> earlyWrites = new ArrayList<>();
    /** Whether the first SETTINGS frame, which must open the connection (RFC 9113 §3.4), is written; guarded by outputWriteLock. */
    private boolean settingsWritten;
    /** Whether outputBuffer has received the first SETTINGS frame; forward thread only. */
    private boolean settingsBuffered;

    /** Writes what this thread put in outputBuffer so far; the first SETTINGS frame among it releases earlyWrites. */
    private void writeBuffered(byte[] output) throws IOException {
        synchronized (outputWriteLock) {
            if (output.length > 0) {
                writeOutput(output);
            }
            if (settingsBuffered && !settingsWritten) {
                settingsWritten = true;
                for (byte[] data : earlyWrites) {
                    writeOutput(data);
                }
                earlyWrites.clear();
            }
        }
    }

    private void flushOutputBuffer() {
        byte[] output = outputBuffer.toByteArray();
        outputBuffer.reset();
        try {
            writeBuffered(output);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Writes frames straight to the socket; frames from other threads wait in earlyWrites until SETTINGS is out. */
    private void writeDirect(byte[] data) {
        synchronized (outputWriteLock) {
            try {
                if (settingsWritten || Thread.currentThread() == forwardThread) {
                    writeOutput(data);
                } else {
                    earlyWrites.add(data);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    // ==== Flow control ====
    // The filter needs whole message bodies, so this proxy buffers DATA and cannot stay transparent to HTTP/2 flow
    // control: the sender would run out of window while the receiver has not seen a byte. Each forward therefore
    // takes over flow control on both of its connections:
    // - every DATA byte read from the sender is acknowledged with our own WINDOW_UPDATE when the read batch ends.
    //   The receiver's WINDOW_UPDATEs are still forwarded (the client's first connection WINDOW_UPDATE is part of its
    //   Akamai fingerprint), minus the bytes our acks already returned, so the sender's windows never grow beyond
    //   what the receiver advertised;
    // - HEADERS and DATA for the receiver wait in per-stream queues, and DATA is written only within the receiver's
    //   connection and stream windows. The peer thread reads the receiver's WINDOW_UPDATE and SETTINGS frames and
    //   writes what they unblock.

    private static final int DEFAULT_WINDOW_SIZE = 0xffff;

    /** Guards the flow-control state below; taken before outputWriteLock, never while holding the peer's flowLock. */
    private final Object flowLock = new Object();

    /** Receiver's connection window for the DATA we write. */
    private long sendConnectionWindow = DEFAULT_WINDOW_SIZE;
    /** Receiver's SETTINGS_INITIAL_WINDOW_SIZE. */
    private int sendInitialWindow = DEFAULT_WINDOW_SIZE;
    /** Streams we may still write to, oldest (lowest id) first. */
    private final Map<Integer, SendStream> sendStreams = new TreeMap<>();
    /**
     * Client streams not yet opened toward the server. The request HEADERS wait until the body has passed the filter,
     * so requests can become ready out of order, but a server rejects a stream id lower than one it has already seen
     * (RFC 9113 §5.1.1): a stream is opened only once every lower one is opened or will never be.
     */
    private final TreeSet<Integer> unopenedStreams = new TreeSet<>();

    /** DATA bytes read from the sender in the current batch, not yet acknowledged. */
    private long recvConnectionUnacked;
    /** DATA bytes read from the sender that no connection WINDOW_UPDATE from the receiver has matched yet. */
    private long recvConnectionUnmatched;
    /** Streams the sender may still send DATA on. */
    private final Map<Integer, RecvStream> recvStreams = new HashMap<>();

    private static class SendStream {
        long window;
        final Deque<PendingFrame> pending = new ArrayDeque<>();

        SendStream(long window) {
            this.window = window;
        }
    }

    /**
     * A HEADERS frame or a DATA payload waiting for the receiver. HEADERS are encoded only when written: HPACK
     * requires header blocks on the wire in the order they were encoded.
     */
    private static class PendingFrame {
        final HttpHeadersFrame headersFrame;
        final byte[] data;
        final boolean endStream;
        int offset;

        PendingFrame(HttpHeadersFrame headersFrame, byte[] data, boolean endStream) {
            this.headersFrame = headersFrame;
            this.data = data;
            this.endStream = endStream;
        }
    }

    private static class RecvStream {
        long unacked;
        long unmatched;
    }

    /** The client opened this stream: it waits for its turn toward the server, and we will answer the client on it. */
    private void onClientStream(int streamId) {
        synchronized (flowLock) {
            unopenedStreams.add(streamId);
        }
        peer.openSendStream(streamId);
    }

    /**
     * This client stream will not be opened toward the server (the filter cancelled or faked its request, or the client
     * reset it), so the streams after it stop waiting. Returns whether it was still waiting.
     */
    private boolean skipStreamOpen(int streamId) {
        synchronized (flowLock) {
            if (!unopenedStreams.remove(streamId)) {
                return false;
            }
            drain();
            return true;
        }
    }

    /** The client opened this stream; from now on its WINDOW_UPDATEs count toward the response we write on it. */
    private void openSendStream(int streamId) {
        synchronized (flowLock) {
            sendStreams.putIfAbsent(streamId, new SendStream(sendInitialWindow));
        }
    }

    private void openRecvStream(int streamId) {
        synchronized (flowLock) {
            recvStreams.putIfAbsent(streamId, new RecvStream());
        }
    }

    private void closeRecvStream(int streamId) {
        synchronized (flowLock) {
            recvStreams.remove(streamId);
        }
    }

    private void closeStream(int streamId) {
        synchronized (flowLock) {
            sendStreams.remove(streamId);
            recvStreams.remove(streamId);
        }
    }

    /** Counts DATA read from the sender, before it is buffered or forwarded. */
    private void onDataRead(int streamId, boolean endStream, int length) {
        synchronized (flowLock) {
            recvConnectionUnacked += length;
            recvConnectionUnmatched += length;
            RecvStream stream = recvStreams.get(streamId);
            if (stream == null) {
                return; // Reset already; the bytes still count against the connection window
            }
            if (endStream) {
                recvStreams.remove(streamId);
            } else {
                stream.unacked += length;
                stream.unmatched += length;
            }
        }
    }

    /** Acknowledges the DATA read in this batch, so the sender never waits for bytes we are holding. */
    private void writeWindowUpdates() {
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        synchronized (flowLock) {
            for (Map.Entry<Integer, RecvStream> entry : recvStreams.entrySet()) {
                RecvStream stream = entry.getValue();
                if (stream.unacked > 0) {
                    encodeWindowUpdateFrame(entry.getKey(), stream.unacked, frames);
                    stream.unacked = 0;
                }
            }
            if (recvConnectionUnacked > 0) {
                encodeWindowUpdateFrame(0, recvConnectionUnacked, frames);
                recvConnectionUnacked = 0;
            }
        }
        if (frames.size() > 0) {
            peer.writeDirect(frames.toByteArray());
        }
    }

    private void encodeWindowUpdateFrame(int streamId, long increment, ByteArrayOutputStream out) {
        ByteBuf frame = frameEncoder.encodeWindowUpdateFrame(streamId, (int) increment);
        try {
            forwardFrameBuf(frame, out);
        } finally {
            frame.release();
        }
    }

    /** Applies a WINDOW_UPDATE from the receiver (read on the peer thread) and writes what it unblocks. */
    private void onWindowUpdate(int streamId, int increment) {
        synchronized (flowLock) {
            if (streamId == 0) {
                sendConnectionWindow += increment;
            } else {
                SendStream stream = sendStreams.get(streamId);
                if (stream == null) {
                    return; // Nothing left to write on this stream
                }
                stream.window += increment;
            }
            drain();
        }
    }

    /**
     * Returns the part of a WINDOW_UPDATE from the receiver that still has to reach the sender. Our acks already
     * returned the window for every byte read, so the increment first pays back the bytes no WINDOW_UPDATE has
     * matched yet; only the rest, which grows the window beyond what was consumed, is forwarded.
     */
    private int windowUpdateToForward(int streamId, int increment) {
        synchronized (flowLock) {
            if (streamId == 0) {
                long matched = Math.min(increment, recvConnectionUnmatched);
                recvConnectionUnmatched -= matched;
                return (int) (increment - matched);
            }
            RecvStream stream = recvStreams.get(streamId);
            if (stream == null) {
                return 0; // The sender can no longer send DATA on this stream
            }
            long matched = Math.min(increment, stream.unmatched);
            stream.unmatched -= matched;
            return (int) (increment - matched);
        }
    }

    /** Applies the receiver's SETTINGS (read on the peer thread) to the stream windows, RFC 9113 §6.9.2. */
    private void onPeerSettingsEnd(HttpSettingsFrame httpSettingsFrame) {
        log.debug("onPeerSettingsEnd server={}, frame={}", server, httpSettingsFrame);
        if (!httpSettingsFrame.isSet(HttpSettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE)) {
            return;
        }
        synchronized (flowLock) {
            int initialWindow = httpSettingsFrame.getValue(HttpSettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE);
            for (SendStream stream : sendStreams.values()) {
                stream.window += initialWindow - sendInitialWindow;
            }
            sendInitialWindow = initialWindow;
            drain();
        }
    }

    private void sendData(int streamId, byte[] data, boolean endStream) {
        sendFrames(streamId, null, data, endStream);
    }

    /**
     * Queues HEADERS (if headersFrame is not null) and DATA (if data is not null) for a stream and writes as much as
     * the receiver's windows allow. The frames go straight to the socket instead of through outputBuffer, so the
     * wire order is the queue order whichever thread writes them.
     */
    private void sendFrames(int streamId, HttpHeadersFrame headersFrame, byte[] data, boolean endStream) {
        synchronized (flowLock) {
            SendStream stream = sendStreams.get(streamId);
            if (stream == null) {
                if (!server || headersFrame == null) {
                    log.debug("sendFrames stream closed server={}, streamId={}", server, streamId);
                    return;
                }
                // A request opens its stream toward the server
                stream = new SendStream(sendInitialWindow);
                sendStreams.put(streamId, stream);
            }
            if (headersFrame != null) {
                stream.pending.add(new PendingFrame(headersFrame, null, headersFrame.isLast()));
            }
            if (data != null) {
                if (headersFrame != null && headersFrame.isLast()) {
                    // The HEADERS already end the stream, as for a fake response with an empty body
                    if (data.length > 0) {
                        log.warn("sendFrames drop DATA after END_STREAM server={}, streamId={}, length={}", server, streamId, data.length);
                    }
                } else {
                    stream.pending.add(new PendingFrame(null, data, endStream));
                }
            }
            drain();
        }
    }

    /** Writes the queued frames the receiver's windows allow, oldest stream first; the caller holds flowLock. */
    private void drain() {
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        sendStreams.entrySet().removeIf(entry -> drain(entry.getKey(), entry.getValue(), frames));
        if (frames.size() > 0) {
            if (Thread.currentThread() == forwardThread) {
                flushOutputBuffer(); // Frames forwarded earlier in this batch go first
            }
            writeDirect(frames.toByteArray());
        }
    }

    /** Returns true once the frame that ends the stream is written. */
    private boolean drain(int streamId, SendStream stream, ByteArrayOutputStream frames) {
        PendingFrame frame;
        while ((frame = stream.pending.peek()) != null) {
            if (frame.headersFrame != null) {
                if (unopenedStreams.contains(streamId)) {
                    if (unopenedStreams.first() != streamId) {
                        return false; // Until the lower client streams are opened
                    }
                    unopenedStreams.remove(streamId);
                }
                encodeHeadersFrame(frame.headersFrame, frames);
            } else {
                int remaining = frame.data.length - frame.offset;
                long window = Math.min(sendConnectionWindow, stream.window);
                if (remaining > 0 && window <= 0) {
                    return false; // Until the receiver's next WINDOW_UPDATE
                }
                int length = (int) Math.min(Math.min(remaining, DEFAULT_CHUNK_SIZE), Math.max(window, 0));
                boolean last = length == remaining;
                ByteBuf dataFrame = frameEncoder.encodeDataFrame(streamId, last && frame.endStream, Unpooled.wrappedBuffer(frame.data, frame.offset, length));
                try {
                    forwardFrameBuf(dataFrame, frames);
                } finally {
                    dataFrame.release();
                }
                frame.offset += length;
                sendConnectionWindow -= length;
                stream.window -= length;
                if (!last) {
                    continue;
                }
            }
            stream.pending.poll();
            if (frame.endStream) {
                return true;
            }
        }
        return false;
    }

    private void encodeHeadersFrame(HttpHeadersFrame headersFrame, ByteArrayOutputStream out) {
        ByteBuf headerBlock;
        try {
            headerBlock = headerEncoder.encode(headersFrame);
        } catch (IOException e) {
            throw new IllegalStateException("encodeHeadersFrame frame=" + headersFrame, e);
        }
        ByteBuf frame = frameEncoder.encodeHeadersFrame(
                headersFrame.getStreamId(),
                headersFrame.isLast(),
                headersFrame.isExclusive(),
                headersFrame.getDependency(),
                headersFrame.getWeight(),
                headerBlock
        );
        try {
            forwardFrameBuf(frame, out);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readPushPromiseFrame(int streamId, int promisedStreamId) {
        log.debug("readPushPromiseFrame server={}, streamId={}, promisedStreamId={}", server, streamId, promisedStreamId);
        throw new UnsupportedOperationException("readPushPromiseFrame");
    }

    @Override
    public void readPingFrame(long data, boolean ack) {
        log.debug("readPingFrame server={}, data={}, ack={}", server, data, ack);
        ByteBuf frame = frameEncoder.encodePingFrame(data, ack);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readGoAwayFrame(int lastStreamId, int errorCode) {
        log.debug("readGoAwayFrame server={}, lastStreamId={}, errorCode={}", server, lastStreamId, errorCode);
        ByteBuf frame = frameEncoder.encodeGoAwayFrame(lastStreamId, errorCode);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readWindowUpdateFrame(int streamId, int windowSizeIncrement) {
        log.debug("readWindowUpdateFrame server={}, streamId={}, windowSizeIncrement={}", server, streamId, windowSizeIncrement);

        if (streamId == 0) {
            if(server) {
                akamai.onWindowUpdateFrame(windowSizeIncrement);
            }
        }

        peer.onWindowUpdate(streamId, windowSizeIncrement);
        int increment = peer.windowUpdateToForward(streamId, windowSizeIncrement);
        if (increment == 0) {
            log.debug("readWindowUpdateFrame already acknowledged by us server={}, streamId={}, windowSizeIncrement={}", server, streamId, windowSizeIncrement);
            return;
        }
        ByteBuf frame = frameEncoder.encodeWindowUpdateFrame(streamId, increment);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readFrameError(String message) {
        canStop = true;
        log.warn("readFrameError: {}", message);
    }

    private static void addHeaders(HttpMessage message, HttpHeaders headers) {
        for (Map.Entry<String, String> e : headers) {
            String name = e.getKey();
            String value = e.getValue();
            if (name.charAt(0) != ':') {
                message.headers().add(name, value);
            }
        }
    }

    /**
     * 交给 {@link com.github.netguard.vpn.tcp.h2.Http2Filter} 的请求与响应的协议版本。这条路径只在
     * SSLProxyV2 的 enterH2Pipeline 分支里用，跑的就是 HTTP/2，写成 HTTP/1.1 等于告诉 filter 一件假事。
     * <p>
     * 带上 minor 是 netty 的要求：HttpVersion 的 VERSION_PATTERN 是 {@code (\S+)/(\d+)\.(\d+)}，
     * "HTTP/2" 会被拒（invalid version format）。
     * <p>
     * 只影响 filter 看到的和日志打印的内容：回写线上的字节来自 headersFrame.headers()，
     * 没有任何地方读这两个对象的 protocolVersion()。
     */
    private static final HttpVersion HTTP_2_0 = HttpVersion.valueOf("HTTP/2.0");

    private static HttpRequest createHttpRequest(HttpHeadersFrame headersFrame, String sessionKey, Akamai akamai) {
        HttpHeaders headers = headersFrame.headers().copy();
        HttpMethod method = HttpMethod.valueOf(headers.get(":method"));
        String uri = headers.get(":path");

        headers.remove(":method");
        headers.remove(":path");


        DefaultHttpRequest request = new DefaultHttpRequest(HTTP_2_0, method, uri, DefaultHttpHeadersFactory.headersFactory().withValidation(false));

        // Remove the scheme header
        headers.remove(":scheme");

        // Replace the H2 host header with the HTTP host header
        String host = headers.get(":authority");
        headers.remove(":authority");
        headers.set(HttpHeaderNames.HOST, host);
        addNetGuardHeaders(headers, headersFrame, sessionKey, akamai);
        addHeaders(request, headers);
        return request;
    }

    private static void addNetGuardHeaders(HttpHeaders headers, HttpHeadersFrame headersFrame, String sessionKey, Akamai akamai) {
        headers.setInt("x-http2-stream-id", headersFrame.getStreamId());
        headers.setInt("x-http2-stream-weight", headersFrame.getWeight());
        headers.set("x-netguard-session", sessionKey);
        String akamaiText = akamai == null ? null : akamai.getText();
        if (akamaiText != null) {
            headers.set("x-akamai-text", akamaiText);
            headers.set("x-akamai-hash", DigestUtils.md5Hex(akamaiText));
        }
    }

    private static HttpResponse createHttpResponse(HttpHeadersFrame headersFrame, String sessionKey, Akamai akamai) {
        HttpHeaders headers = headersFrame.headers().copy();
        // Create the first line of the request from the name/value pairs
        HttpResponseStatus status = HttpResponseStatus.valueOf(headers.getInt(":status"));
        headers.remove(":status");
        HttpResponse response = new DefaultHttpResponse(HTTP_2_0, status, DefaultHttpHeadersFactory.headersFactory().withValidation(false));
        addNetGuardHeaders(headers, headersFrame, sessionKey, akamai);
        addHeaders(response, headers);
        return response;
    }

}

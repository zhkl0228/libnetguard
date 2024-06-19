package com.twitter.http2;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.StreamForward;
import com.github.netguard.vpn.tcp.h2.CancelResult;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import com.github.netguard.vpn.tcp.h2.HttpHeaderBlockDecoder;
import com.github.netguard.vpn.tcp.h2.HttpHeaderBlockEncoder;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameRstStream;
import edu.baylor.cs.csi5321.spdy.frames.H2Util;
import eu.faircode.netguard.Packet;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

public class HttpFrameForward extends StreamForward implements HttpFrameDecoderDelegate {

    private static final Logger log = LoggerFactory.getLogger(HttpFrameForward.class);

    private final NetGuardFrameDecoder frameDecoder;
    private final HttpFrameEncoder frameEncoder;

    private final HttpHeaderBlockDecoder headerDecoder;
    private final HttpHeaderBlockEncoder headerEncoder;

    private final Http2Session session;
    private final Http2Filter filter;
    private final String sessionKey;

    public HttpFrameForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket, InspectorVpn vpn, String hostName,
                            Http2Session session, Packet packet) {
        super(inputStream, outputStream, server, clientSocketAddress, serverSocketAddress, countDownLatch, socket, vpn, hostName, true, packet);
        this.frameDecoder = new NetGuardFrameDecoder(server, this);
        this.frameEncoder = new HttpFrameEncoder();

        headerDecoder = new HttpHeaderBlockDecoder(0x4000, 0x10000);
        headerEncoder = new HttpHeaderBlockEncoder(0x100);

        this.session = session;
        this.filter = packetCapture == null ? null : packetCapture.getH2Filter();
        this.sessionKey = session.toString();
    }

    private HttpFrameForward peer;

    public HttpFrameForward setPeer(HttpFrameForward peer) {
        this.peer = peer;
        peer.peer = this;
        return this;
    }

    private boolean canStop;

    @Override
    protected boolean forward(byte[] buf) throws IOException {
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
                if (dataInput.available() > 0) {
                    continue;
                }

                byte[] output = outputBuffer.toByteArray();
                outputBuffer.reset();
                if (input != null) {
                    log.debug("forward server={}, inHash={}, outHash={}, input={}, output={}", server, DigestUtil.md5Hex(input), DigestUtil.md5Hex(output), HexUtil.encodeHexStr(input), HexUtil.encodeHexStr(output));
                }
                if (log.isTraceEnabled()) {
                    String clientIp = clientSocketAddress.getAddress().getHostAddress();
                    int clientPort = clientSocketAddress.getPort();
                    String serverIp = serverSocketAddress.getAddress().getHostAddress();
                    int serverPort = serverSocketAddress.getPort();
                    String date = new SimpleDateFormat("[HH:mm:ss SSS]").format(new Date());
                    if (server) {
                        File outbound = new File("target/" + String.format("%s:%d_%s:%d_outbound.txt", clientIp, clientPort, serverIp, serverPort));
                        File forward = new File("target/" + String.format("%s:%d_%s:%d_outbound_forward.txt", clientIp, clientPort, serverIp, serverPort));
                        FileUtil.appendUtf8Lines(Collections.singletonList(date + HexUtil.encodeHexStr(input)), outbound);
                        FileUtil.appendUtf8Lines(Collections.singletonList(date + HexUtil.encodeHexStr(output)), forward);
                    } else {
                        File inbound = new File("target/" + String.format("%s:%d_%s:%d_inbound.txt", clientIp, clientPort, serverIp, serverPort));
                        File forward = new File("target/" + String.format("%s:%d_%s:%d_inbound_forward.txt", clientIp, clientPort, serverIp, serverPort));
                        FileUtil.appendUtf8Lines(Collections.singletonList(date + HexUtil.encodeHexStr(input)), inbound);
                        FileUtil.appendUtf8Lines(Collections.singletonList(date + HexUtil.encodeHexStr(output)), forward);
                    }
                }
                if (output.length > 0) {
                    outputStream.write(output);
                    outputStream.flush();

                    if (packetCapture != null) {
                        if (server) {
                            packetCapture.onSSLProxyTx(clientSocketAddress, serverSocketAddress, output);
                        } else {
                            packetCapture.onSSLProxyRx(clientSocketAddress, serverSocketAddress, output);
                        }
                    }
                }
                byte[] response;
                while ((response = delayResponseQueue.poll()) != null) {
                    outputStream.write(response);
                    outputStream.flush();
                }
            }
            return true;
        } catch (SocketTimeoutException ignored) {
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
            if (stream == null) {
                log.warn("readDataFrame not exists stream: {}", streamId);
                return;
            }
            data.readBytes(stream.buffer, data.readableBytes());
            if (stream.longPolling) {
                if (server) {
                    handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), endStream, false, streamId);
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
                    handleResponse(stream.httpHeadersFrame, stream.buffer.toByteArray(), outputBuffer);
                }
                stream.buffer.reset();
            } else if (server) {
                HttpHeaders headers = stream.httpHeadersFrame.headers();
                if (!headers.contains(HttpHeaderNames.CONTENT_LENGTH) &&
                        !headers.contains(HttpHeaderNames.TRANSFER_ENCODING) &&
                        !headers.contains(HttpHeaderNames.CONTENT_RANGE)) {
                    stream.longPolling = true;
                    handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), false, true, streamId);
                    stream.buffer.reset();
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("readDataFrame", e);
        } finally {
            data.release();
        }
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

    private void writeMessage(HttpHeadersFrame headersFrame, byte[] data, boolean endStreamOnFlush, ByteArrayOutputStream outputBuffer) {
        log.debug("writeMessage settingsReady={}, headersFrame={}, endStreamOnFlush={}", settingsReady, headersFrame, endStreamOnFlush);
        ByteBuf byteBuf = data == null || data.length == 0 ? Unpooled.EMPTY_BUFFER : Unpooled.wrappedBuffer(data);
        try {
            {
                ByteBuf headerBlock = headerEncoder.encode(headersFrame);
                ByteBuf frame = frameEncoder.encodeHeadersFrame(
                        headersFrame.getStreamId(),
                        headersFrame.isLast(),
                        headersFrame.isExclusive(),
                        headersFrame.getDependency(),
                        headersFrame.getWeight(),
                        headerBlock
                );
                try {
                    // Writes of compressed data must occur in order
                    forwardFrameBuf(frame, outputBuffer);
                } finally {
                    frame.release();
                }
            }

            if (byteBuf.isReadable()) {
                while (byteBuf.isReadable()) {
                    ByteBuf partialDataFrame = byteBuf.readSlice(Math.min(byteBuf.readableBytes(), DEFAULT_CHUNK_SIZE));
                    log.debug("writeMessage server={}, partialDataFrame={}, byteBuf={}", server, partialDataFrame, byteBuf);
                    boolean endStream = !byteBuf.isReadable() && endStreamOnFlush;
                    ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStream, partialDataFrame);
                    forwardFrameBuf(frame, outputBuffer);
                }
            } else if (data != null) {
                ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
                forwardFrameBuf(frame, outputBuffer);
            }
        } catch (IOException e) {
            log.warn("writeMessage server={}", server, e);
        } finally {
            byteBuf.release();
        }
    }

    private void writeCancelStreamFrame(int streamId) {
        readRstStreamFrame(streamId, H2FrameRstStream.ErrorCode.CANCEL.ordinal());
    }

    private void handlePollingRequest(HttpHeadersFrame headersFrame, byte[] requestData, boolean endStreamOnFlush, boolean newStream, int streamId) {
        HttpRequest request = filter == null ? null : createHttpRequest(headersFrame, sessionKey, null);
        if (filter != null) {
            CancelResult result = filter.cancelRequest(request, requestData == null ? new byte[0] : requestData, true);
            if (result != null) {
                if (result.cancel) {
                    peer.writeCancelStreamFrame(streamId);
                } else {
                    throw new UnsupportedOperationException("response=" + result.response);
                }
                return;
            }
        }
        byte[] data = filter == null ? requestData : filter.filterPollingRequest(new Http2SessionKey(session, headersFrame.getStreamId()), request, requestData, newStream);
        if (newStream) {
            writeMessage(headersFrame, data, endStreamOnFlush, outputBuffer);
        } else {
            ByteBuf byteBuf = Unpooled.wrappedBuffer(data);
            ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
            try {
                forwardFrameBuf(frame, outputBuffer);
            } finally {
                frame.release();
            }
        }
    }

    private void handlePollingResponse(HttpHeadersFrame headersFrame, byte[] responseData, boolean endStreamOnFlush) {
        byte[] data = filter == null ? responseData : filter.filterPollingResponse(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpResponse(headersFrame, sessionKey),
                responseData, endStreamOnFlush);
        ByteBuf byteBuf = Unpooled.wrappedBuffer(data);
        ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
    }

    private final Queue<byte[]> delayResponseQueue = new LinkedBlockingQueue<>();

    private void handleRequest(HttpHeadersFrame headersFrame, byte[] requestData, int streamId) {
        HttpRequest request = filter == null ? null : createHttpRequest(headersFrame, sessionKey, akamai);
        if (filter != null) {
            CancelResult result = filter.cancelRequest(request, requestData == null ? new byte[0] : requestData, false);
            if (result != null) {
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
                    filter.filterRequest(new Http2SessionKey(session, headersFrame.getStreamId()), request,
                            headersFrame.headers(), requestData == null ? new byte[0] : requestData);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    peer.handleResponse(fakeHeadersFrame, responseData, baos);
                    if (settingsReady) {
                        IoUtil.copy(new ByteArrayInputStream(baos.toByteArray()), peer.outputStream);
                    } else {
                        peer.delayResponseQueue.offer(baos.toByteArray());
                    }
                }
                return;
            }
        }
        byte[] data = filter == null ? requestData : filter.filterRequest(new Http2SessionKey(session, headersFrame.getStreamId()), request,
                headersFrame.headers(), requestData == null ? new byte[0] : requestData);
        if (data == null) {
            throw new IllegalStateException();
        }
        writeMessage(headersFrame, requestData == null && data.length == 0 ? null : data, true, outputBuffer);
    }

    private void handleResponse(HttpHeadersFrame headersFrame, byte[] responseData, ByteArrayOutputStream outputBuffer) {
        byte[] data = filter == null ? responseData : filter.filterResponse(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpResponse(headersFrame, sessionKey),
                headersFrame.headers(), responseData == null ? new byte[0] : responseData);
        if (data == null) {
            throw new IllegalStateException();
        }
        HttpHeaders headers = headersFrame.headers();
        headers.setInt("x-http2-stream-id", headersFrame.getStreamId());
        headers.setInt("x-http2-stream-weight", headersFrame.getWeight());
        headers.set("x-netguard-session", sessionKey);
        writeMessage(headersFrame, responseData == null && data.length == 0 ? null : data, true, outputBuffer);
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
            if (server) {
                handleRequest(httpHeadersFrame, null, httpHeadersFrame.getStreamId());
            } else {
                handleResponse(httpHeadersFrame, null, outputBuffer);
            }
        } else {
            Stream stream = new Stream(httpHeadersFrame);
            Stream old = streamMap.put(httpHeadersFrame.getStreamId(), stream);
            if (old != null) {
                log.warn("readHeaderBlockEnd replace exists stream old={}", old);
            }

            Stream peerStream;
            if (!server &&
                    (peerStream = peer.streamMap.get(httpHeadersFrame.getStreamId())) != null &&
                    peerStream.longPolling) {
                stream.longPolling = true;
                writeMessage(stream.httpHeadersFrame, null, false, outputBuffer);
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
        ByteBuf frame = frameEncoder.encodeRstStreamFrame(streamId, errorCode);
        try {
            forwardFrameBuf(frame, outputBuffer);
        } finally {
            frame.release();
        }
        streamMap.remove(streamId);
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

    private boolean settingsReady;

    private void onPeerSettingsEnd(HttpSettingsFrame httpSettingsFrame) {
        log.debug("onPeerSettingsEnd server={}, settingsReady={}, frame={}", server, settingsReady, httpSettingsFrame);
        if (httpSettingsFrame.isAck()) {
            settingsReady = true;
        }
    }

    @Override
    public void readSettingsEnd() {
        log.debug("readSettingsEnd server={}, frame={}", server, httpSettingsFrame);

        if (server) {
            akamai.onHttpSettingsFrame(httpSettingsFrame);
        }

        peer.onPeerSettingsEnd(httpSettingsFrame);
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

        ByteBuf frame = frameEncoder.encodeWindowUpdateFrame(streamId, windowSizeIncrement);
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

    private static HttpRequest createHttpRequest(HttpHeadersFrame headersFrame, String sessionKey, Akamai akamai) {
        HttpHeaders headers = headersFrame.headers().copy();
        HttpMethod method = HttpMethod.valueOf(headers.get(":method"));
        String uri = headers.get(":path");

        headers.remove(":method");
        headers.remove(":path");


        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, uri, false);

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
            headers.set("x-akamai-hash", DigestUtil.md5Hex(akamaiText));
        }
    }

    private static HttpResponse createHttpResponse(HttpHeadersFrame headersFrame, String sessionKey) {
        HttpHeaders headers = headersFrame.headers().copy();
        // Create the first line of the request from the name/value pairs
        HttpResponseStatus status = HttpResponseStatus.valueOf(headers.getInt(":status"));
        headers.remove(":status");
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, status, false);
        addNetGuardHeaders(headers, headersFrame, sessionKey, null);
        addHeaders(response, headers);
        return response;
    }

}

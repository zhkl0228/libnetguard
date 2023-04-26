package com.twitter.http2;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.ssl.StreamForward;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import com.github.netguard.vpn.ssl.h2.Http2Session;
import com.github.netguard.vpn.ssl.h2.Http2SessionKey;
import edu.baylor.cs.csi5321.spdy.frames.SpdyUtil;
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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

public class HttpFrameForward extends StreamForward implements HttpFrameDecoderDelegate {

    private static final Logger log = LoggerFactory.getLogger(HttpFrameForward.class);

    private static final int DEFAULT_HEADER_TABLE_SIZE = 0x1000;

    private final HttpFrameDecoder frameDecoder;
    private final HttpFrameEncoder frameEncoder;

    private final HttpHeaderBlockDecoder httpHeaderBlockDecoder;
    private final com.github.netguard.vpn.ssl.h2.HttpHeaderBlockEncoder httpHeaderBlockEncoder;

    private final Http2Session session;
    private final Http2Filter filter;

    private int lastHeaderTableSize = Integer.MAX_VALUE;
    private int minHeaderTableSize = Integer.MAX_VALUE;
    private boolean changeEncoderHeaderTableSize;

    public HttpFrameForward(InputStream inputStream, OutputStream outputStream, boolean server, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket, IPacketCapture packetCapture, String hostName,
                            Http2Session session) {
        super(inputStream, outputStream, server, clientIp, serverIp, clientPort, serverPort, countDownLatch, socket, packetCapture, hostName, true);
        this.frameDecoder = new HttpFrameDecoder(server, this);
        this.frameEncoder = new HttpFrameEncoder();

        httpHeaderBlockDecoder = new HttpHeaderBlockDecoder(0x4000, DEFAULT_HEADER_TABLE_SIZE);
        httpHeaderBlockEncoder = new com.github.netguard.vpn.ssl.h2.HttpHeaderBlockEncoder(DEFAULT_HEADER_TABLE_SIZE);

        this.session = session;
        this.filter = packetCapture == null ? null : packetCapture.getH2Filter();
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
                    packetCapture.onSSLProxyTx(clientIp, serverIp, clientPort, serverPort, preface);
                }
            }
            while (!canStop) {
                int header = dataInput.readInt();
                int length = (header >>> 8) & SpdyUtil.MASK_LENGTH_HEADER;
                log.debug("read frame length server={}, length={}", server, length);
                dataInput.readFully(buf, 0, 5);
                byteBuf.writeInt(header);
                byteBuf.writeBytes(buf, 0, 5);
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

                byte[] output = outputBuffer.toByteArray();
                outputBuffer.reset();
                if (input != null) {
                    log.debug("forward server={}, inHash={}, outHash={}, input={}, output={}", server, DigestUtil.md5Hex(input), DigestUtil.md5Hex(output), HexUtil.encodeHexStr(input), HexUtil.encodeHexStr(output));
                }
                if (log.isTraceEnabled()) {
                    String date = new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss]").format(new Date());
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
                            packetCapture.onSSLProxyTx(clientIp, serverIp, clientPort, serverPort, output);
                        } else {
                            packetCapture.onSSLProxyRx(clientIp, serverIp, clientPort, serverPort, output);
                        }
                    }
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
                return;
            }
            data.readBytes(stream.buffer, data.readableBytes());
            if (stream.longPolling) {
                if (server) {
                    handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), endStream, false);
                } else {
                    handlePollingResponse(stream.httpHeadersFrame, stream.buffer.toByteArray(), endStream);
                }
                stream.buffer.reset();
                return;
            }
            if (endStream) {
                streamMap.remove(streamId);
                if (server) {
                    handleRequest(stream.httpHeadersFrame, stream.buffer.toByteArray());
                } else {
                    handleResponse(stream.httpHeadersFrame, stream.buffer.toByteArray());
                }
                stream.buffer.reset();
            } else if (server) {
                HttpHeaders headers = stream.httpHeadersFrame.headers();
                if (!headers.contains(HttpHeaderNames.CONTENT_LENGTH) &&
                        !headers.contains(HttpHeaderNames.CONTENT_ENCODING)) {
                    stream.longPolling = true;
                    handlePollingRequest(stream.httpHeadersFrame, stream.buffer.toByteArray(), false, true);
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
        httpHeadersFrame = new DefaultHttpHeadersFrame(streamId);
        httpHeadersFrame.setLast(endStream);
        httpHeadersFrame.setExclusive(exclusive);
        httpHeadersFrame.setDependency(dependency);
        httpHeadersFrame.setWeight(weight);
    }

    @Override
    public void readHeaderBlock(ByteBuf headerBlockFragment) {
        log.debug("readHeaderBlock server={}, headerBlockFragment={}", server, headerBlockFragment);
        try {
            httpHeaderBlockDecoder.decode(headerBlockFragment, httpHeadersFrame);
        } catch (IOException e) {
            throw new IllegalStateException("readHeaderBlock frame=" + httpHeadersFrame, e);
        } finally {
            headerBlockFragment.release();
        }
    }

    private final Map<Integer, Stream> streamMap = new HashMap<>();

    private static final int DEFAULT_CHUNK_SIZE = 0x1000;

    private void writeMessage(HttpHeadersFrame headersFrame, byte[] data, boolean endStreamOnFlush) {
        ByteBuf byteBuf = Unpooled.wrappedBuffer(data == null ? new byte[0] : data);
        try {
            synchronized (httpHeaderBlockEncoder) {
                ByteBuf headerBlock = httpHeaderBlockEncoder.encode(headersFrame);
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
                    forwardFrameBuf(frame);
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
                    forwardFrameBuf(frame);
                }
            } else if (data != null) {
                ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
                forwardFrameBuf(frame);
            }
        } catch (IOException e) {
            log.warn("writeMessage server={}", server, e);
        } finally {
            byteBuf.release();
        }
    }

    private void handlePollingRequest(HttpHeadersFrame headersFrame, byte[] requestData, boolean endStreamOnFlush, boolean newStream) {
        byte[] data = filter == null ? requestData : filter.filterPollingRequest(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpRequest(headersFrame.headers().copy()),
                headersFrame.headers(), requestData,
                newStream);
        if (newStream) {
            writeMessage(headersFrame, data, endStreamOnFlush);
        } else {
            ByteBuf byteBuf = Unpooled.wrappedBuffer(data);
            ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
            try {
                forwardFrameBuf(frame);
            } finally {
                frame.release();
            }
        }
    }

    private void handlePollingResponse(HttpHeadersFrame headersFrame, byte[] responseData, boolean endStreamOnFlush) {
        byte[] data = filter == null ? responseData : filter.filterPollingResponse(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpResponse(headersFrame.headers().copy()),
                headersFrame.headers(), responseData, endStreamOnFlush);
        ByteBuf byteBuf = Unpooled.wrappedBuffer(data);
        ByteBuf frame = frameEncoder.encodeDataFrame(headersFrame.getStreamId(), endStreamOnFlush, byteBuf);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
    }

    private void handleRequest(HttpHeadersFrame headersFrame, byte[] requestData) {
        byte[] data = filter == null ? requestData : filter.filterRequest(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpRequest(headersFrame.headers().copy()),
                headersFrame.headers(), requestData);
        writeMessage(headersFrame, data, true);
    }

    private void handleResponse(HttpHeadersFrame headersFrame, byte[] responseData) {
        byte[] data = filter == null ? responseData : filter.filterResponse(new Http2SessionKey(session, headersFrame.getStreamId()),
                createHttpResponse(headersFrame.headers().copy()),
                headersFrame.headers(), responseData);
        writeMessage(headersFrame, data, true);
    }

    @Override
    public void readHeaderBlockEnd() {
        if (httpHeadersFrame.isTruncated()) {
            throw new UnsupportedOperationException("frame=" + httpHeadersFrame);
        }

        httpHeaderBlockDecoder.endHeaderBlock(httpHeadersFrame);
        log.debug("readHeaderBlockEnd server={}, frame={}", server, httpHeadersFrame);

        if (httpHeadersFrame.isLast()) {
            if (server) {
                handleRequest(httpHeadersFrame, null);
            } else {
                handleResponse(httpHeadersFrame, null);
            }
        } else {
            Stream stream = new Stream(httpHeadersFrame);
            streamMap.put(httpHeadersFrame.getStreamId(), stream);

            Stream peerStream;
            if (!server &&
                    (peerStream = peer.streamMap.get(httpHeadersFrame.getStreamId())) != null &&
                    peerStream.longPolling) {
                stream.longPolling = true;
                writeMessage(stream.httpHeadersFrame, null, false);
            }
        }
        httpHeadersFrame = null;
    }

    @Override
    public void readPriorityFrame(int streamId, boolean exclusive, int dependency, int weight) {
        log.debug("readPriorityFrame server={}, streamId={}, exclusive={}, dependency={}, weight={}", server, streamId, exclusive, dependency, weight);
        ByteBuf frame = frameEncoder.encodePriorityFrame(streamId, exclusive, dependency, weight);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readRstStreamFrame(int streamId, int errorCode) {
        log.debug("readRstStreamFrame server={}, streamId={}, errorCode={}", server, streamId, errorCode);
        ByteBuf frame = frameEncoder.encodeRstStreamFrame(streamId, errorCode);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
        streamMap.remove(streamId);
    }

    private HttpSettingsFrame httpSettingsFrame;
    private boolean changeDecoderHeaderTableSize;
    private int headerTableSize;

    @Override
    public void readSettingsFrame(boolean ack) {
        httpSettingsFrame = new DefaultHttpSettingsFrame();
        httpSettingsFrame.setAck(ack);
        log.debug("readSettingsFrame server={}, ack={}, changeDecoderHeaderTableSize={}, headerTableSize={}", server, ack, changeDecoderHeaderTableSize, headerTableSize);

        if (ack && changeDecoderHeaderTableSize) {
            httpHeaderBlockDecoder.setMaxHeaderTableSize(headerTableSize);
            changeDecoderHeaderTableSize = false;
        }
    }

    @Override
    public void readSetting(int id, int value) {
        log.debug("readSetting server={}, id={}, value={}", server, id, value);
        httpSettingsFrame.setValue(id, value);

        if (id == HttpSettingsFrame.SETTINGS_HEADER_TABLE_SIZE) {
            // Ignore 'negative' values -- they are too large for java
            if (value >= 0) {
                changeEncoderHeaderTableSize = true;
                lastHeaderTableSize = value;
                if (lastHeaderTableSize < minHeaderTableSize) {
                    minHeaderTableSize = lastHeaderTableSize;
                }
            }
        }
    }

    private void onPeerSettingsEnd(HttpSettingsFrame httpSettingsFrame) {
        int newHeaderTableSize =
                httpSettingsFrame.getValue(HttpSettingsFrame.SETTINGS_HEADER_TABLE_SIZE);
        if (newHeaderTableSize >= 0) {
            headerTableSize = newHeaderTableSize;
            changeDecoderHeaderTableSize = true;
        }
        log.debug("onPeerSettingsEnd server={}, changeDecoderHeaderTableSize={}, headerTableSize={}, , frame={}", server, changeDecoderHeaderTableSize, headerTableSize, httpSettingsFrame);
    }

    @Override
    public void readSettingsEnd() {
        log.debug("readSettingsEnd server={}, changeEncoderHeaderTableSize={}, minHeaderTableSize={}, lastHeaderTableSize={}, frame={}", server, changeEncoderHeaderTableSize, minHeaderTableSize, lastHeaderTableSize, httpSettingsFrame);
        if (changeEncoderHeaderTableSize) {
            synchronized (httpHeaderBlockEncoder) {
                httpHeaderBlockEncoder.setDecoderMaxHeaderTableSize(minHeaderTableSize);
                httpHeaderBlockEncoder.setDecoderMaxHeaderTableSize(lastHeaderTableSize);
            }
            changeEncoderHeaderTableSize = false;
            lastHeaderTableSize = Integer.MAX_VALUE;
            minHeaderTableSize = Integer.MAX_VALUE;
        }

        peer.onPeerSettingsEnd(httpSettingsFrame);
        ByteBuf frame = frameEncoder.encodeSettingsFrame(httpSettingsFrame);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
        httpSettingsFrame = null;
    }

    private final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();

    private void forwardFrameBuf(ByteBuf byteBuf) {
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
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readGoAwayFrame(int lastStreamId, int errorCode) {
        log.debug("readGoAwayFrame server={}, lastStreamId={}, errorCode={}", server, lastStreamId, errorCode);
        ByteBuf frame = frameEncoder.encodeGoAwayFrame(lastStreamId, errorCode);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readWindowUpdateFrame(int streamId, int windowSizeIncrement) {
        log.debug("readWindowUpdateFrame server={}, streamId={}, windowSizeIncrement={}", server, streamId, windowSizeIncrement);
        ByteBuf frame = frameEncoder.encodeWindowUpdateFrame(streamId, windowSizeIncrement);
        try {
            forwardFrameBuf(frame);
        } finally {
            frame.release();
        }
    }

    @Override
    public void readFrameError(String message) {
        canStop = true;
        log.warn("readFrameError: {}", message);
    }

    private static void addHeaders(HttpHeaders headers, HttpMessage message) {
        for (Map.Entry<String, String> e : headers) {
            String name = e.getKey();
            String value = e.getValue();
            if (name.charAt(0) != ':') {
                message.headers().add(name, value);
            }
        }
    }

    private static HttpRequest createHttpRequest(HttpHeaders headers) {
        HttpMethod method = HttpMethod.valueOf(headers.get(":method"));
        String url = headers.get(":path");

        headers.remove(":method");
        headers.remove(":path");


        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, url);

        // Remove the scheme header
        headers.remove(":scheme");

        // Replace the SPDY host header with the HTTP host header
        String host = headers.get(":authority");
        headers.remove(":authority");
        headers.set(HttpHeaderNames.HOST, host);

        addHeaders(headers, request);

        return request;
    }

    private static HttpResponse createHttpResponse(HttpHeaders headers) {
        // Create the first line of the request from the name/value pairs
        HttpResponseStatus status = HttpResponseStatus.valueOf(Integer.parseInt(headers.get(":status")));
        headers.remove(":status");
        return new DefaultHttpResponse(HttpVersion.HTTP_1_1, status);
    }

}

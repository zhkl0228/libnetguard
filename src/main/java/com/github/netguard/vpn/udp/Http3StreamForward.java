package com.github.netguard.vpn.udp;

import cn.hutool.core.codec.Base64;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.tcp.h2.CancelResult;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import com.twitter.http2.NetGuardHttp2Headers;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.DefaultHttpHeadersFactory;
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
import io.netty.incubator.codec.http3.Http3SettingsFrame;
import net.luminis.qpack.Decoder;
import net.luminis.qpack.Encoder;
import net.luminis.quic.QuicConstants;
import net.luminis.quic.QuicStream;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class Http3StreamForward extends QuicStreamForward {

    private static final Logger log = LoggerFactory.getLogger(Http3StreamForward.class);

    protected final Http2SessionKey sessionKey;
    protected final Http2Filter http2Filter;
    private final Buffer buffer = new ChainBuffer();

    Http3StreamForward(boolean server, boolean bidirectional, QuicStream from, QuicStream to,
                       Http2SessionKey sessionKey, Http2Filter http2Filter) {
        super(server, bidirectional, from, to);
        this.sessionKey = sessionKey;
        this.http2Filter = http2Filter;
    }

    private boolean readControlStreamType;

    @Override
    void doForward(byte[] buf, int read, DataOutputStream outputStream) throws IOException {
        buffer.addLast(Arrays.copyOfRange(buf, 0, read));
        if (!bidirectional && !readControlStreamType) {
            readControlStreamType = true;
            int type = buffer.get() & 0xff;
            switch (type) {
                case HTTP3_CONTROL_STREAM_TYPE:
                    break;
                case HTTP3_QPACK_ENCODER_STREAM_TYPE: {
                    while (!buffer.isEOB()) {
                        int instruction = buffer.get() & 0xff;
                        log.warn("HTTP3_QPACK_ENCODER_STREAM_TYPE instruction=0x{}", Integer.toHexString(instruction));
                    }
                    return;
                }
                case HTTP3_QPACK_DECODER_STREAM_TYPE: {
                    while (!buffer.isEOB()) {
                        int instruction = buffer.get() & 0xff;
                        if ((instruction >>> 6) == 1) {
                            int streamId = instruction & 0x3f;
                            log.debug("cancel streamId={}", streamId);
                        } else {
                            log.warn("HTTP3_QPACK_DECODER_STREAM_TYPE instruction=0x{}", Integer.toHexString(instruction));
                        }
                    }
                    return;
                }
                default:
                    log.warn("control stream type {} is not supported", type);
                    break;
            }
            outputStream.write(type);
        }
        while (!buffer.isEOB()) {
            log.debug("{} readableBytes={}, read={}, from={}, to={}", server ? "Server" : "Client", buffer.readableBytes(), read, from, to);
            if (forwardHttp3Frame(outputStream)) {
                break;
            }
        }
    }

    private byte[] headerBlock;
    private final List<byte[]> dataBlocks = new ArrayList<>(3);
    private Http3StreamForward peer;
    final void setPeer(Http3StreamForward peer) {
        if (this == peer) {
            throw new IllegalArgumentException();
        }
        this.peer = peer;
    }

    private void handleResponse(HttpResponse response, byte[] responseData) {
        List<Map.Entry<String, String>> headers = response.headers().entries();
        headers.add(0, new AbstractMap.SimpleEntry<>(":status", String.valueOf(response.status().code())));
        ByteBuffer bb = encoder.compressHeaders(headers);
        bb.flip();
        headerBlock = new byte[bb.remaining()];
        bb.get(headerBlock);
        setDataBlocks(responseData);
        log.debug("{} handleResponse headerBlock.length={}, dataBlockSize={}", server ? "Server" : "Client", headerBlock.length, dataBlocks.size());
        from.abortReading(QuicConstants.TransportErrorCode.NO_ERROR.value);
    }

    private void setDataBlocks(byte[] data) {
        if (data == null) {
            return;
        }
        dataBlocks.clear();
        for (int i = 0; i < data.length; i += 1024) {
            byte[] block = Arrays.copyOfRange(data, i, Math.min(i + 1024, data.length));
            dataBlocks.add(block);
        }
    }

    @Override
    void onEOF(DataOutputStream outputStream) throws IOException {
        if(headerBlock == null) {
            log.debug("onEOF dataBlockSize={}", dataBlocks.size());
            return;
        }

        try {
            List<Map.Entry<String, String>> headerList = decoder.decodeStream(new ByteArrayInputStream(headerBlock));
            Map<String, String> map = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : headerList) {
                map.put(entry.getKey(), entry.getValue());
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (byte[] data : dataBlocks) {
                baos.write(data);
            }
            if (server) {
                byte[] requestData = baos.toByteArray();
                HttpRequest request = createHttpRequest(map, sessionKey.toString(), from.getStreamId());
                log.debug("onEOF headers={}, request={}", headerList, request);
                CancelResult result = http2Filter.cancelRequest(request, requestData, false);
                if (result != null) {
                    if (result.cancel) {
                        from.resetStream(QuicConstants.TransportErrorCode.CONNECTION_REFUSED.value);
                    } else {
                        byte[] responseData = result.responseData;
                        HttpResponse response = result.response;
                        response.headers().set("x-netguard-fake-response", sessionKey.toString());
                        http2Filter.filterRequest(sessionKey, request, request.headers(), requestData);
                        peer.handleResponse(response, responseData);
                    }
                    return;
                }
                HttpHeaders headers = new NetGuardHttp2Headers();
                for(Map.Entry<String, String> entry : headerList) {
                    headers.add(entry.getKey(), entry.getValue());
                }
                byte[] data = http2Filter.filterRequest(sessionKey, request, headers, requestData);
                if (data == null) {
                    throw new IllegalStateException();
                }
                log.debug("onEOF filter request headers={}", headers);
                headerList = headers.entries();
                setDataBlocks(data);
            } else {
                HttpResponse response = createHttpResponse(map, sessionKey.toString(), from.getStreamId());
                log.debug("onEOF headers={}, response={}", headerList, response);
                HttpHeaders headers = new NetGuardHttp2Headers();
                for(Map.Entry<String, String> entry : headerList) {
                    headers.add(entry.getKey(), entry.getValue());
                }
                byte[] responseData = baos.toByteArray();
                byte[] data = http2Filter.filterResponse(sessionKey, response, headers, responseData);
                if (data == null) {
                    throw new IllegalStateException();
                }
                log.debug("onEOF filter response headers={}", headers);
                headers.setInt("x-http2-stream-id", from.getStreamId());
                headers.set("x-netguard-session", sessionKey.toString());
                headerList = headers.entries();
                setDataBlocks(data);
            }
            headerList.sort((o1, o2) -> o1.getKey().compareToIgnoreCase(o2.getKey()));
            log.debug("onEOF forwardHttp3Frame dataBlocksSize={}, headers={}", dataBlocks.size(), headerList);
            ByteBuffer bb = encoder.compressHeaders(headerList);
            writeVariableLengthInteger(outputStream, HTTP3_HEADERS_FRAME_TYPE);
            writeVariableLengthInteger(outputStream, bb.limit());
            outputStream.write(bb.array(), 0, bb.limit());
            for(byte[] data : dataBlocks) {
                writeData(outputStream, HTTP3_DATA_FRAME_TYPE, data);
            }
        } finally {
            headerBlock = null;
            dataBlocks.clear();
        }
    }

    private static HttpResponse createHttpResponse(Map<String, String> headers, String sessionKey, int streamId) {
        HttpResponseStatus status = HttpResponseStatus.valueOf(Integer.parseInt(headers.get(":status")));
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, status, DefaultHttpHeadersFactory.headersFactory().withValidation(false));
        addNetGuardHeaders(headers, sessionKey, streamId);
        addHeaders(response, headers);
        return response;
    }

    private static HttpRequest createHttpRequest(Map<String, String> headers, String sessionKey, int streamId) {
        HttpMethod method = HttpMethod.valueOf(headers.get(":method"));
        String uri = headers.get(":path");

        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, uri, DefaultHttpHeadersFactory.headersFactory().withValidation(false));

        // Replace the H2 host header with the HTTP host header
        String host = headers.get(":authority");
        headers.put(HttpHeaderNames.HOST.toString(), host);
        addNetGuardHeaders(headers, sessionKey, streamId);
        addHeaders(request, headers);
        return request;
    }

    private static void addNetGuardHeaders(Map<String, String> headers, String sessionKey, int streamId) {
        headers.put("x-http2-stream-id", String.valueOf(streamId));
        headers.put("x-netguard-session", sessionKey);
    }

    private static void addHeaders(HttpMessage message, Map<String, String> headers) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String name = e.getKey();
            String value = e.getValue();
            if (name.charAt(0) != ':') {
                message.headers().add(name, value);
            }
        }
    }

    private long type = -1;
    private int payLoadLength = -1;
    private final Decoder decoder = new Decoder();
    private final Encoder encoder = new Encoder();

    private boolean forwardHttp3Frame(DataOutputStream outputStream) throws IOException {
        {
            buffer.mark();
            if (type == -1) {
                byte b = buffer.get();
                int typeLen = numBytesForVariableLengthInteger(b);
                buffer.reset();
                if (buffer.readableBytes() < typeLen) {
                    type = -1;
                    return true;
                }
                type = readVariableLengthInteger(buffer, typeLen);
                if (isReservedHttp2FrameType(type)) {
                    writeVariableLengthInteger(outputStream, type);
                    type = -1;
                    return false;
                }
            }
            if (buffer.isEOB()) {
                return true;
            }
        }
        {
            buffer.mark();
            if (payLoadLength == -1) {
                byte b = buffer.get();
                int payloadLen = numBytesForVariableLengthInteger(b);
                buffer.reset();
                assert payloadLen <= 8;
                if (buffer.readableBytes() < payloadLen) {
                    payLoadLength = -1;
                    return true;
                }
                long len = readVariableLengthInteger(buffer, payloadLen);
                payLoadLength = (int) len;
            }
        }
        boolean reservedFrameType = isReservedFrameType(type);
        log.debug("{} forwardHttp3Frame type={}, reservedFrameType={}, payLoadLength={}, readableBytes={}, from={}, to={}", server ? "Server" : "Client", type, reservedFrameType, payLoadLength, buffer.readableBytes(), from, to);
        if (type > Integer.MAX_VALUE && !reservedFrameType) {
            buffer.skip(payLoadLength);
            return true;
        }
        if (payLoadLength > buffer.readableBytes()) {
            return true;
        }
        byte[] data = new byte[payLoadLength];
        buffer.gets(data);
        if (log.isDebugEnabled()) {
            log.debug("{}", Inspector.inspectString(data, (server ? "Server" : "Client") + " forwardHttp3Frame type=" + type + ", from=" + from + ", to=" + to));
        }
        switch ((int) type) {
            case HTTP3_DATA_FRAME_TYPE: {
                dataBlocks.add(data);
                break;
            }
            case HTTP3_HEADERS_FRAME_TYPE: {
                if (headerBlock == null) {
                    headerBlock = data;
                } else {
                    log.warn("Already has headerBlock");
                }
                break;
            }
            case HTTP3_SETTINGS_FRAME_TYPE: {
                ByteArrayOutputStream baos = new ByteArrayOutputStream(50);
                DataOutputStream dos = new DataOutputStream(baos);
                Buffer bb = new ChainBuffer(data);
                while (!bb.isEOB()) {
                    long key, value;
                    {
                        bb.mark();
                        byte b = bb.get();
                        bb.reset();
                        int len = numBytesForVariableLengthInteger(b);
                        key = readVariableLengthInteger(bb, len);
                    }
                    {
                        bb.mark();
                        byte b = bb.get();
                        bb.reset();
                        int len = numBytesForVariableLengthInteger(b);
                        value = readVariableLengthInteger(bb, len);
                    }
                    log.debug("settings key={}, value={}, readableBytes={}", key, value, bb.readableBytes());
                    if (key == Http3SettingsFrame.HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY ||
                            key == Http3SettingsFrame.HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE ||
                            key == Http3SettingsFrame.HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS) {
                        writeVariableLengthInteger(dos, key);
                        writeVariableLengthInteger(dos, value);
                    }
                }
                if (baos.size() > 0) {
                    writeData(outputStream, HTTP3_SETTINGS_FRAME_TYPE, baos.toByteArray());
                }
                break;
            }
            default: {
                if (reservedFrameType) {
                    break;
                }
                log.warn("{} forwardHttp3Frame type={}, length={}, data={}, from={}, to={}", (server ? "Server" : "Client"), type, data.length, Base64.encode(data), from, to);
                break;
            }
        }
        type = -1;
        payLoadLength = -1;
        return false;
    }

    private static final int HTTP3_DATA_FRAME_TYPE = 0x0;
    private static final int HTTP3_HEADERS_FRAME_TYPE = 0x1;
    private static final int HTTP3_SETTINGS_FRAME_TYPE = 0x4;

    private static final int HTTP3_CONTROL_STREAM_TYPE = 0x00;
    private static final int HTTP3_QPACK_ENCODER_STREAM_TYPE = 0x02;
    private static final int HTTP3_QPACK_DECODER_STREAM_TYPE = 0x03;

    private void writeData(DataOutputStream outputStream, long type, byte[] data) throws IOException {
        writeVariableLengthInteger(outputStream, type);
        writeVariableLengthInteger(outputStream, data.length);
        outputStream.write(data);
    }

    private static void writeVariableLengthInteger(DataOutputStream out, long value) throws IOException {
        int numBytes = numBytesForVariableLengthInteger(value);
        writeVariableLengthInteger(out, value, numBytes);
    }

    /**
     * Write the variable length integer into the {@link ByteBuf}.
     * See <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-16">
     *     Variable-Length Integer Encoding</a>.
     */
    private static void writeVariableLengthInteger(DataOutputStream out, long value, int numBytes) throws IOException {
        switch (numBytes) {
            case 1:
                out.writeByte((byte) value);
                break;
            case 2:
                value |= 0x40 << 8;
                out.writeShort((short) value);
                break;
            case 4:
                value |= 0x80L << 24;
                out.writeInt((int) value);
                break;
            case 8:
                value |= 0xc0L << 56;
                out.writeLong(value);
                break;
            default:
                throw new IllegalArgumentException();
        }
    }

    private static long readVariableLengthInteger(Buffer in, int len) {
        switch (len) {
            case 1:
                return in.get() & 0xff;
            case 2:
                return in.getUnsignedShort() & 0x3fff;
            case 4:
                return in.getInt() & 0x3fffffff;
            case 8:
                return in.getLong() & 0x3fffffffffffffffL;
            default:
                throw new IllegalArgumentException("readVariableLengthInteger len=" + len);
        }
    }

    private static int numBytesForVariableLengthInteger(byte b) {
        byte val = (byte) (b >> 6);
        if ((val & 1) != 0) {
            if ((val & 2) != 0) {
                return 8;
            }
            return 2;
        }
        if ((val & 2) != 0) {
            return 4;
        }
        return 1;
    }

    private static int numBytesForVariableLengthInteger(long value) {
        if (value <= 63) {
            return 1;
        }
        if (value <= 16383) {
            return 2;
        }
        if (value <= 1073741823) {
            return 4;
        }
        if (value <= 4611686018427387903L) {
            return 8;
        }
        throw new IllegalArgumentException("numBytesForVariableLengthInteger value=" + value);
    }

    private static boolean isReservedHttp2FrameType(long type) {
        switch ((int) type) {
            // Reserved types that were used in HTTP/2
            // https://tools.ietf.org/html/draft-ietf-quic-http-32#section-11.2.1
            case 0x2:
            case 0x6:
            case 0x8:
            case 0x9:
                return true;
            default:
                return false;
        }
    }

    // See https://tools.ietf.org/html/draft-ietf-quic-http-32#section-7.2.8
    private static final long MIN_RESERVED_FRAME_TYPE = 0x1f + 0x21;
    private static final long MAX_RESERVED_FRAME_TYPE = 0x1f * (long) Integer.MAX_VALUE + 0x21;

    private static boolean isReservedFrameType(long type) {
        return type >= MIN_RESERVED_FRAME_TYPE && type <= MAX_RESERVED_FRAME_TYPE;
    }

}

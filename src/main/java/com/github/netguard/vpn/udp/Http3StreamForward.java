package com.github.netguard.vpn.udp;

import cn.hutool.core.codec.Base64;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import io.netty.buffer.ByteBuf;
import net.luminis.qpack.Decoder;
import net.luminis.qpack.Encoder;
import net.luminis.quic.QuicStream;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
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

    @Override
    void doForward(byte[] buf, int read, DataOutputStream outputStream) throws IOException {
        buffer.addLast(Arrays.copyOfRange(buf, 0, read));
        while (!buffer.isEOB()) {
            log.debug("{} readableBytes={}, read={}, from={}, to={}", server ? "Server" : "Client", buffer.readableBytes(), read, from, to);
            if (forwardHttp3Frame(outputStream)) {
                break;
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
                writeData(outputStream, type, data);
                break;
            }
            case HTTP3_HEADERS_FRAME_TYPE: {
                List<Map.Entry<String, String>> headers = decoder.decodeStream(new ByteArrayInputStream(data));
                log.debug("forwardHttp3Frame headers={}", headers);
                ByteBuffer bb = encoder.compressHeaders(headers);
                writeVariableLengthInteger(outputStream, type);
                writeVariableLengthInteger(outputStream, bb.limit());
                outputStream.write(bb.array(), 0, bb.limit());
                break;
            }
            default: {
                writeData(outputStream, type, data);
                log.warn("forwardHttp3Frame type={}, data={}", type, Base64.encode(data));
                break;
            }
        }
        type = -1;
        payLoadLength = -1;
        return false;
    }

    private static final int HTTP3_DATA_FRAME_TYPE = 0x0;
    private static final int HTTP3_HEADERS_FRAME_TYPE = 0x1;

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
                return in.get();
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

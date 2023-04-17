package com.github.netguard.vpn.ssl;

import com.github.netguard.vpn.IPacketCapture;
import com.twitter.hpack.Decoder;
import com.twitter.hpack.HeaderListener;
import com.twitter.http2.DefaultHttpHeadersFrame;
import com.twitter.http2.DefaultHttpSettingsFrame;
import com.twitter.http2.HttpFrameDecoder;
import com.twitter.http2.HttpFrameDecoderDelegate;
import com.twitter.http2.HttpFrameEncoder;
import com.twitter.http2.HttpHeadersFrame;
import com.twitter.http2.HttpSettingsFrame;
import edu.baylor.cs.csi5321.spdy.frames.SpdyUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

class HttpFrameForward extends StreamForward implements HttpFrameDecoderDelegate {

    private static final Logger log = LoggerFactory.getLogger(HttpFrameForward.class);

    private static final int DEFAULT_HEADER_TABLE_SIZE = 0x1000;

    private final HttpFrameDecoder frameDecoder;
    private final HttpFrameEncoder frameEncoder;

    private final Decoder decoder;

    HttpFrameForward(InputStream inputStream, OutputStream outputStream, boolean server, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket, IPacketCapture packetCapture, String hostName) {
        super(inputStream, outputStream, server, clientIp, serverIp, clientPort, serverPort, countDownLatch, socket, packetCapture, hostName);
        this.decoder = new Decoder(0x4000, DEFAULT_HEADER_TABLE_SIZE);
        this.frameDecoder = new HttpFrameDecoder(server, this);
        this.frameEncoder = new HttpFrameEncoder();
    }

    private boolean canStop;
    private IOException writeException;

    @Override
    protected boolean forward(byte[] buf) throws IOException {
        ByteBuf byteBuf = Unpooled.buffer();
        DataInputStream dataInput = new DataInputStream(inputStream);
        try {
            if (server) {
                byte[] preface = new byte[24];
                dataInput.readFully(preface);
                byteBuf.writeBytes(preface);
                frameDecoder.decode(byteBuf);
                outputStream.write(preface);
                outputStream.flush();

                if (packetCapture != null) {
                    packetCapture.onSSLProxyTX(clientIp, serverIp, clientPort, serverPort, preface);
                }
            }
            while (!canStop) {
                int header = dataInput.readInt();
                int length = (header >>> 8) & SpdyUtil.MASK_LENGTH_HEADER;
                dataInput.readFully(buf, 0, 5);
                byteBuf.writeInt(header);
                byteBuf.writeBytes(buf, 0, 5);
                while (length > 0) {
                    int read = dataInput.read(buf, 0, Math.min(length, buf.length));
                    if (read == -1) {
                        break;
                    }
                    byteBuf.writeBytes(buf, 0, read);
                    length -= read;
                }
                frameDecoder.decode(byteBuf);
                if (writeException != null) {
                    throw writeException;
                }
            }
            return true;
        } catch (SocketTimeoutException ignored) {
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
        log.debug("readDataFrame server={}, streamId={}, endStream={}, endSegment={}, data={}", server, streamId, endStream, endSegment, data);
        ByteBuf byteBuf = frameEncoder.encodeDataFrame(streamId, endStream, data);
        forwardFrameBuf(byteBuf);
    }

    private HttpHeadersFrame httpHeadersFrame;
    private ByteBuf headerBlock;

    @Override
    public void readHeadersFrame(int streamId, boolean endStream, boolean endSegment, boolean exclusive, int dependency, int weight) {
        log.debug("readHeadersFrame server={}, streamId={}, endStream={}, endSegment={}, exclusive={}, dependency={}, weight={}", server, streamId, endStream, endSegment, exclusive, dependency, weight);

        HttpHeadersFrame httpHeadersFrame = new DefaultHttpHeadersFrame(streamId);
        httpHeadersFrame.setLast(endStream);
        httpHeadersFrame.setExclusive(exclusive);
        httpHeadersFrame.setDependency(dependency);
        httpHeadersFrame.setWeight(weight);
        this.httpHeadersFrame = httpHeadersFrame;
        this.headerBlock = Unpooled.buffer();
    }

    @Override
    public void readHeaderBlock(ByteBuf headerBlockFragment) {
        log.debug("readHeaderBlock server={}, headerBlockFragment={}, frame={}", server, headerBlockFragment, httpHeadersFrame);
        headerBlock.writeBytes(headerBlockFragment);
    }

    @Override
    public void readHeaderBlockEnd() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            headerBlock.readBytes(baos, headerBlock.readableBytes());
            byte[] block = baos.toByteArray();
            decoder.decode(new ByteArrayInputStream(block), new HeaderListener() {
                @Override
                public void addHeader(byte[] name, byte[] value, boolean sensitive) {
                    httpHeadersFrame.headers().add(new String(name, StandardCharsets.UTF_8), new String(value, StandardCharsets.UTF_8));
                }
            });
            ByteBuf byteBuf = frameEncoder.encodeHeadersFrame(httpHeadersFrame.getStreamId(), httpHeadersFrame.isLast(), httpHeadersFrame.isExclusive(), httpHeadersFrame.getDependency(), httpHeadersFrame.getWeight(), Unpooled.wrappedBuffer(block));
            forwardFrameBuf(byteBuf);
        } catch (IOException e) {
            throw new IllegalStateException("readHeaderBlockEnd", e);
        }
        log.debug("readHeaderBlockEnd server={}, headerBlock={}, frame={}", server, headerBlock, httpHeadersFrame);
        headerBlock = null;
        httpHeadersFrame = null;
    }

    @Override
    public void readPriorityFrame(int streamId, boolean exclusive, int dependency, int weight) {
        log.debug("readPriorityFrame server={}, streamId={}, exclusive={}, dependency={}, weight={}", server, streamId, exclusive, dependency, weight);
        ByteBuf byteBuf = frameEncoder.encodePriorityFrame(streamId, exclusive, dependency, weight);
        forwardFrameBuf(byteBuf);
    }

    @Override
    public void readRstStreamFrame(int streamId, int errorCode) {
        log.debug("readRstStreamFrame server={}, streamId={}, errorCode={}", server, streamId, errorCode);
        ByteBuf byteBuf = frameEncoder.encodeRstStreamFrame(streamId, errorCode);
        forwardFrameBuf(byteBuf);
    }

    private HttpSettingsFrame httpSettingsFrame;

    @Override
    public void readSettingsFrame(boolean ack) {
        httpSettingsFrame = new DefaultHttpSettingsFrame();
        httpSettingsFrame.setAck(ack);
        log.debug("readSettingsFrame server={}, ack={}", server, ack);
    }

    @Override
    public void readSetting(int id, int value) {
        httpSettingsFrame.setValue(id, value);
        log.debug("readSetting server={}, id={}, value={}", server, id, value);
        switch (id) {
            case HttpSettingsFrame.SETTINGS_HEADER_TABLE_SIZE:
                // Ignore 'negative' values -- they are too large for java
                if (value >= 0) {
                    decoder.setMaxHeaderTableSize(value);
                }
                break;
            case HttpSettingsFrame.SETTINGS_MAX_HEADER_LIST_SIZE:
            case HttpSettingsFrame.SETTINGS_ENABLE_PUSH:
            case HttpSettingsFrame.SETTINGS_MAX_CONCURRENT_STREAMS:
            case HttpSettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE:
            case HttpSettingsFrame.SETTINGS_MAX_FRAME_SIZE:
                break;
            default:
                // Ignore Unknown Settings
                log.warn("readSetting id={}, value={}", id, value);
                break;
        }
    }

    @Override
    public void readSettingsEnd() {
        log.debug("readSettingsEnd server={}, frame={}", server, httpSettingsFrame);
        ByteBuf byteBuf = frameEncoder.encodeSettingsFrame(httpSettingsFrame);
        forwardFrameBuf(byteBuf);
        httpSettingsFrame = null;
    }

    private void forwardFrameBuf(ByteBuf byteBuf) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byteBuf.readBytes(baos, byteBuf.readableBytes());
            byte[] data = baos.toByteArray();
            outputStream.write(data);
            outputStream.flush();

            if (packetCapture != null) {
                if (server) {
                    packetCapture.onSSLProxyTX(clientIp, serverIp, clientPort, serverPort, data);
                } else {
                    packetCapture.onSSLProxyRX(clientIp, serverIp, clientPort, serverPort, data);
                }
            }
        } catch (IOException e) {
            writeException = e;
        }
    }

    @Override
    public void readPushPromiseFrame(int streamId, int promisedStreamId) {
        log.debug("readPushPromiseFrame server={}, streamId={}, promisedStreamId={}", server, streamId, promisedStreamId);
        throw new UnsupportedOperationException();
    }

    @Override
    public void readPingFrame(long data, boolean ack) {
        log.debug("readPingFrame server={}, data={}, ack={}", server, data, ack);
        ByteBuf byteBuf = frameEncoder.encodePingFrame(data, ack);
        forwardFrameBuf(byteBuf);
    }

    @Override
    public void readGoAwayFrame(int lastStreamId, int errorCode) {
        log.debug("readGoAwayFrame server={}, lastStreamId={}, errorCode={}", server, lastStreamId, errorCode);
        ByteBuf byteBuf = frameEncoder.encodeGoAwayFrame(lastStreamId, errorCode);
        forwardFrameBuf(byteBuf);
    }

    @Override
    public void readWindowUpdateFrame(int streamId, int windowSizeIncrement) {
        log.debug("readWindowUpdateFrame server={}, streamId={}, windowSizeIncrement={}", server, streamId, windowSizeIncrement);
        ByteBuf byteBuf = frameEncoder.encodeWindowUpdateFrame(streamId, windowSizeIncrement);
        forwardFrameBuf(byteBuf);
    }

    @Override
    public void readFrameError(String message) {
        canStop = true;
        log.warn("readFrameError: {}", message);
    }

}

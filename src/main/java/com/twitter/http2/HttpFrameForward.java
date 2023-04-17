package com.twitter.http2;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.ssl.StreamForward;
import edu.baylor.cs.csi5321.spdy.frames.SpdyUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.CountDownLatch;

public class HttpFrameForward extends StreamForward implements HttpFrameDecoderDelegate {

    private static final Logger log = LoggerFactory.getLogger(HttpFrameForward.class);

    private static final int DEFAULT_HEADER_TABLE_SIZE = 0x1000;

    private final HttpFrameDecoder frameDecoder;
    private final HttpFrameEncoder frameEncoder;

    private final HttpHeaderBlockDecoder httpHeaderBlockDecoder;
    private final com.github.netguard.vpn.ssl.h2.HttpHeaderBlockEncoder httpHeaderBlockEncoder;

    private int lastHeaderTableSize = Integer.MAX_VALUE;
    private int minHeaderTableSize = Integer.MAX_VALUE;
    private boolean changeEncoderHeaderTableSize;

    public HttpFrameForward(InputStream inputStream, OutputStream outputStream, boolean server, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket, IPacketCapture packetCapture, String hostName) {
        super(inputStream, outputStream, server, clientIp, serverIp, clientPort, serverPort, countDownLatch, socket, packetCapture, hostName);
        this.frameDecoder = new HttpFrameDecoder(server, this);
        this.frameEncoder = new HttpFrameEncoder();

        httpHeaderBlockDecoder = new HttpHeaderBlockDecoder(0x4000, DEFAULT_HEADER_TABLE_SIZE);
        httpHeaderBlockEncoder = new com.github.netguard.vpn.ssl.h2.HttpHeaderBlockEncoder(DEFAULT_HEADER_TABLE_SIZE);
    }

    private HttpFrameForward peer;

    public HttpFrameForward setPeer(HttpFrameForward peer) {
        this.peer = peer;
        peer.peer = this;
        return this;
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
        } finally {
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
        log.debug("readDataFrame server={}, streamId={}, endStream={}, endSegment={}, data={}", server, streamId, endStream, endSegment, data);
        ByteBuf byteBuf = frameEncoder.encodeDataFrame(streamId, endStream, data);
        forwardFrameBuf(byteBuf);
    }

    private HttpHeadersFrame httpHeadersFrame;

    @Override
    public void readHeadersFrame(int streamId, boolean endStream, boolean endSegment, boolean exclusive, int dependency, int weight) {
        log.debug("readHeadersFrame server={}, streamId={}, endStream={}, endSegment={}, exclusive={}, dependency={}, weight={}", server, streamId, endStream, endSegment, exclusive, dependency, weight);

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
        }
    }

    @Override
    public void readHeaderBlockEnd() {
        try {
            synchronized (httpHeaderBlockEncoder) {
                ByteBuf frame = frameEncoder.encodeHeadersFrame(
                        httpHeadersFrame.getStreamId(),
                        httpHeadersFrame.isLast(),
                        httpHeadersFrame.isExclusive(),
                        httpHeadersFrame.getDependency(),
                        httpHeadersFrame.getWeight(),
                        httpHeaderBlockEncoder.encode(httpHeadersFrame)
                );
                // Writes of compressed data must occur in order
                forwardFrameBuf(frame);
            }
        } catch (IOException e) {
            log.error("readHeaderBlockEnd server={}", server, e);
        }

        httpHeaderBlockDecoder.endHeaderBlock(httpHeadersFrame);
        log.debug("readHeaderBlockEnd server={}, frame={}", server, httpHeadersFrame);
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
        throw new UnsupportedOperationException("readPushPromiseFrame");
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

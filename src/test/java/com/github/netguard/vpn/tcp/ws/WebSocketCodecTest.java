package com.github.netguard.vpn.tcp.ws;

import junit.framework.TestCase;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 校验 {@link WebSocketCodec} 的增量解析(HTTP/2 分块场景)与编解码往返。
 */
public class WebSocketCodecTest extends TestCase {

    private static WebSocketCodec newCodec() {
        WebSocketSession session = new WebSocketSession(
                new InetSocketAddress("127.0.0.1", 1), new InetSocketAddress("127.0.0.1", 2), "example.com");
        return new WebSocketCodec(session, false);
    }

    private static byte[] payload(int len) {
        byte[] p = new byte[len];
        for (int i = 0; i < len; i++) {
            p[i] = (byte) (i * 31 + 7);
        }
        return p;
    }

    /** 把多帧拼成一条字节流,按固定块大小喂给解析器,断言帧完整还原。 */
    public void testIncrementalParseAcrossChunks() throws Exception {
        int[][] specs = {
                {WebSocketFrame.OPCODE_TEXT, 5, 1},      // 小载荷,masked
                {WebSocketFrame.OPCODE_BINARY, 200, 0},  // 126 扩展长度,unmasked
                {WebSocketFrame.OPCODE_BINARY, 70000, 1},// 127 扩展长度,masked
                {WebSocketFrame.OPCODE_PING, 0, 0},      // 空载荷控制帧
        };
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        List<byte[]> expectedPayloads = new ArrayList<>();
        List<Integer> expectedOpcodes = new ArrayList<>();
        for (int[] s : specs) {
            byte[] p = payload(s[1]);
            stream.write(WebSocketCodec.encode(s[0], true, p, s[2] == 1));
            expectedPayloads.add(p);
            expectedOpcodes.add(s[0]);
        }
        byte[] all = stream.toByteArray();

        for (int chunk : new int[]{1, 3, 7, 64, 4096, all.length}) {
            WebSocketCodec codec = newCodec();
            List<WebSocketCodec.Frame> got = new ArrayList<>();
            for (int off = 0; off < all.length; off += chunk) {
                int len = Math.min(chunk, all.length - off);
                got.addAll(codec.parse(Arrays.copyOfRange(all, off, off + len)));
            }
            assertEquals("chunk=" + chunk + " frame count", specs.length, got.size());
            for (int i = 0; i < specs.length; i++) {
                WebSocketCodec.Frame f = got.get(i);
                assertEquals("chunk=" + chunk + " opcode", (int) expectedOpcodes.get(i), f.opcode);
                assertTrue("fin", f.fin);
                assertTrue("payload chunk=" + chunk + " idx=" + i,
                        Arrays.equals(expectedPayloads.get(i), f.unmaskedRaw()));
            }
        }
    }

    /** 单帧被拆到最后一个字节前都不应产出,补齐后立即产出。 */
    public void testPartialFrameBuffering() {
        byte[] frame = WebSocketCodec.encode(WebSocketFrame.OPCODE_TEXT, true, payload(50), true);
        WebSocketCodec codec = newCodec();
        List<WebSocketCodec.Frame> got = codec.parse(Arrays.copyOfRange(frame, 0, frame.length - 1));
        assertTrue("incomplete frame must not emit", got.isEmpty());
        got = codec.parse(new byte[]{frame[frame.length - 1]});
        assertEquals("frame emitted after completion", 1, got.size());
    }

    /** 两帧粘在一个块里,应一次解析出两帧。 */
    public void testTwoFramesInOneChunk() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        byte[] a = WebSocketCodec.encode(WebSocketFrame.OPCODE_TEXT, true, "hello".getBytes(), false);
        byte[] b = WebSocketCodec.encode(WebSocketFrame.OPCODE_TEXT, true, "world".getBytes(), false);
        stream.write(a, 0, a.length);
        stream.write(b, 0, b.length);
        List<WebSocketCodec.Frame> got = newCodec().parse(stream.toByteArray());
        assertEquals(2, got.size());
        assertEquals("hello", new String(got.get(0).unmaskedRaw()));
        assertEquals("world", new String(got.get(1).unmaskedRaw()));
    }

    /** rsv1=false(无压缩)时 decode 应原样返回解掩码结果。 */
    public void testDecodeNoDeflate() throws Exception {
        WebSocketCodec codec = newCodec();
        byte[] p = "plain-text".getBytes();
        assertTrue(Arrays.equals(p, codec.decode(p, false)));
    }

    /** permessage-deflate:压缩帧(rsv1=1)应还原为原文。 */
    public void testDecodePermessageDeflate() throws Exception {
        WebSocketSession session = new WebSocketSession(
                new InetSocketAddress("127.0.0.1", 1), new InetSocketAddress("127.0.0.1", 2), "example.com");
        WebSocketCodec.parseExtensions("permessage-deflate; server_no_context_takeover", session);
        assertTrue(session.isPermessageDeflate());
        WebSocketCodec codec = new WebSocketCodec(session, false); // server->client 解码方向

        byte[] original = "The quick brown fox jumps over the lazy dog. The quick brown fox.".getBytes();
        // RFC 7692:raw deflate 后去掉尾部的 4 字节 0x00 0x00 0xFF 0xFF
        java.util.zip.Deflater deflater = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(original);
        deflater.finish();
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        byte[] buf = new byte[256];
        while (!deflater.finished()) {
            int n = deflater.deflate(buf, 0, buf.length, java.util.zip.Deflater.SYNC_FLUSH);
            if (n == 0) {
                break;
            }
            compressed.write(buf, 0, n);
        }
        deflater.end();
        byte[] payload = compressed.toByteArray();
        // 去掉尾部 00 00 FF FF(若存在)
        if (payload.length >= 4 && payload[payload.length - 4] == 0 && payload[payload.length - 3] == 0
                && (payload[payload.length - 2] & 0xFF) == 0xFF && (payload[payload.length - 1] & 0xFF) == 0xFF) {
            payload = Arrays.copyOfRange(payload, 0, payload.length - 4);
        }

        byte[] decoded = codec.decode(payload, true);
        assertEquals(new String(original), new String(decoded));
    }
}

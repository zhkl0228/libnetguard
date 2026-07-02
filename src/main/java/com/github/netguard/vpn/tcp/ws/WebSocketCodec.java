package com.github.netguard.vpn.tcp.ws;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * WebSocket 帧编解码器,供 HTTP/1.1(经典 Upgrade,阻塞读)与 HTTP/2(RFC 8441,分块推送)两条路径复用。
 * <ul>
 *     <li>{@link #readFrame(DataInputStream)}:阻塞式逐帧读取(HTTP/1.1)。</li>
 *     <li>{@link #parse(byte[])}:增量式推送解析,残帧内部缓存(HTTP/2 DATA 分块)。</li>
 *     <li>{@link #decode(byte[], boolean)}:解掩码结果 + permessage-deflate 解压(持有本方向 Inflater,支持 context takeover)。</li>
 *     <li>{@link #encode(int, boolean, byte[], boolean)}:未压缩重编码(mask 由方向决定)。</li>
 * </ul>
 * 一个实例绑定一个方向(由 {@code server} 指示 client-&gt;server),不是线程安全的读侧;encode 为静态无状态。
 */
public class WebSocketCodec {

    /** 一个原始 WebSocket 帧(payload 可能仍被掩码)。 */
    public static class Frame {
        public boolean fin;
        public boolean rsv1;
        public int opcode;
        public boolean masked;
        public byte[] maskKey;
        public byte[] payload; // 原始(可能被掩码)
        public byte[] raw;     // 完整原始帧字节(透传用)

        public byte[] unmaskedRaw() {
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

    private final WebSocketSession session;
    private final boolean server; // true => 本方向为 client->server
    private Inflater inflater;     // 仅解码方向按需创建(context takeover 时跨消息复用)

    public WebSocketCodec(WebSocketSession session, boolean server) {
        this.session = session;
        this.server = server;
    }

    // ==== 增量解析(HTTP/2) ====
    private byte[] pending = new byte[0];

    /**
     * 追加一段字节,尽可能多地解析出完整帧;不足一帧的尾部残留内部缓存,下次调用续拼。
     */
    public List<Frame> parse(byte[] more) {
        if (more != null && more.length > 0) {
            byte[] merged = new byte[pending.length + more.length];
            System.arraycopy(pending, 0, merged, 0, pending.length);
            System.arraycopy(more, 0, merged, pending.length, more.length);
            pending = merged;
        }
        List<Frame> frames = new ArrayList<>();
        int off = 0;
        while (true) {
            int consumed = tryParseOne(pending, off, frames);
            if (consumed <= 0) {
                break;
            }
            off += consumed;
        }
        if (off > 0) {
            byte[] rest = new byte[pending.length - off];
            System.arraycopy(pending, off, rest, 0, rest.length);
            pending = rest;
        }
        return frames;
    }

    /** 尝试从 buf[off..] 解析一帧;成功返回消耗字节数并把帧加入 out,不足返回 0。 */
    private static int tryParseOne(byte[] buf, int off, List<Frame> out) {
        int avail = buf.length - off;
        if (avail < 2) {
            return 0;
        }
        int p = off;
        int b0 = buf[p++] & 0xFF;
        int b1 = buf[p++] & 0xFF;
        boolean masked = (b1 & 0x80) != 0;
        long len = b1 & 0x7F;
        if (len == 126) {
            if (buf.length - p < 2) {
                return 0;
            }
            len = ((buf[p] & 0xFFL) << 8) | (buf[p + 1] & 0xFFL);
            p += 2;
        } else if (len == 127) {
            if (buf.length - p < 8) {
                return 0;
            }
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | (buf[p + i] & 0xFFL);
            }
            p += 8;
        }
        int maskLen = masked ? 4 : 0;
        if (len > Integer.MAX_VALUE - 16) {
            throw new IllegalStateException("frame too large: " + len);
        }
        if (buf.length - p < maskLen + len) {
            return 0; // 尚不完整
        }
        Frame f = new Frame();
        f.fin = (b0 & 0x80) != 0;
        f.rsv1 = (b0 & 0x40) != 0;
        f.opcode = b0 & 0x0F;
        f.masked = masked;
        if (masked) {
            f.maskKey = new byte[]{buf[p], buf[p + 1], buf[p + 2], buf[p + 3]};
            p += 4;
        }
        f.payload = new byte[(int) len];
        System.arraycopy(buf, p, f.payload, 0, (int) len);
        p += (int) len;
        f.raw = new byte[p - off];
        System.arraycopy(buf, off, f.raw, 0, f.raw.length);
        out.add(f);
        return p - off;
    }

    // ==== 阻塞逐帧读取(HTTP/1.1) ====
    public static Frame readFrame(DataInputStream in) throws IOException {
        int b0 = in.read();
        if (b0 < 0) {
            return null;
        }
        int b1 = in.readUnsignedByte();
        Frame f = new Frame();
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
    public byte[] decode(byte[] unmasked, boolean rsv1) throws IOException {
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
    public static byte[] encode(int opcode, boolean fin, byte[] payload, boolean mask) {
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

    /**
     * 解析 Sec-WebSocket-Extensions 的值(不含头名),写入 session 的 permessage-deflate 协商结果。
     * 可多次调用(不同头值),命中 permessage-deflate 即置位。
     */
    public static void parseExtensions(String extensionsValue, WebSocketSession session) {
        if (extensionsValue == null) {
            return;
        }
        String line = extensionsValue.toLowerCase();
        if (line.contains("permessage-deflate")) {
            session.permessageDeflate = true;
            session.serverNoContextTakeover = line.contains("server_no_context_takeover");
            session.clientNoContextTakeover = line.contains("client_no_context_takeover");
        }
    }
}

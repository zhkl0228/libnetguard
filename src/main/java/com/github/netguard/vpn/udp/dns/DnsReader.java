package com.github.netguard.vpn.udp.dns;

import org.apache.commons.codec.binary.Hex;

import java.util.Arrays;

/**
 * 按 RFC 1035 线格式读一条完整的 DNS 报文。所有越界、格式不符都直接抛
 * {@link IllegalArgumentException}，异常信息里带出错位置和整条报文的十六进制，
 * 拿到异常就等于拿到了补分支用的样本。
 */
class DnsReader {

    static final int HEADER_LENGTH = 12;

    /** 名字线格式（含长度字节和结尾的 0）的上限，RFC 1035 §3.1。 */
    private static final int MAX_NAME_WIRE_LENGTH = 255;

    private final byte[] data;
    private final int base;
    private final int end;
    private int pos;

    DnsReader(byte[] data, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException("offset=" + offset + ", length=" + length + ", data.length=" + data.length);
        }
        this.data = data;
        this.base = offset;
        this.end = offset + length;
        this.pos = offset;
    }

    /** 相对报文开头的当前偏移。 */
    int position() {
        return pos - base;
    }

    /** 退回到报文内一个已读过的偏移，用于先偷看类型再整条重读。 */
    DnsReader rewind(int position) {
        if (position < 0 || base + position > pos) {
            throw new IllegalArgumentException("rewind to " + position + " beyond current " + position());
        }
        pos = base + position;
        return this;
    }

    int remaining() {
        return end - pos;
    }

    int u8() {
        require(1);
        return data[pos++] & 0xff;
    }

    int u16() {
        require(2);
        int v = ((data[pos] & 0xff) << 8) | (data[pos + 1] & 0xff);
        pos += 2;
        return v;
    }

    long u32() {
        require(4);
        long v = ((long) (data[pos] & 0xff) << 24) | ((data[pos + 1] & 0xff) << 16) | ((data[pos + 2] & 0xff) << 8) | (data[pos + 3] & 0xff);
        pos += 4;
        return v;
    }

    byte[] bytes(int n) {
        require(n);
        byte[] out = new byte[n];
        System.arraycopy(data, pos, out, 0, n);
        pos += n;
        return out;
    }

    /** 按报文内偏移取一段已读过的字节，不移动读位置。 */
    byte[] slice(int offset, int length) {
        return Arrays.copyOfRange(data, base + offset, base + offset + length);
    }

    /**
     * 读一个域名，返回不带结尾点的形式（根为空串）。
     *
     * @param allowPointers 是否允许压缩指针。样本里查询报文、应答的问题段、HTTPS rdata 都没有
     *                      出现过指针（RFC 9460 也禁止 SVCB/HTTPS 压缩），这些位置传 false。
     *                      指针只许严格向前跳（每跳一次目标都比上一次小），这既是样本里的
     *                      形态，也保证不会成环。
     */
    String name(boolean allowPointers) {
        int start = pos;
        int cursor = pos;
        int limit = start - base; // 下一个指针目标必须小于它
        boolean jumped = false;
        int wireLength = 0;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (cursor >= end) {
                throw fail(cursor, "name runs past end of message");
            }
            int len = data[cursor] & 0xff;
            int kind = len & 0xc0;
            if (kind == 0xc0) {
                if (!allowPointers) {
                    throw fail(cursor, "compression pointer where none expected");
                }
                if (cursor + 1 >= end) {
                    throw fail(cursor, "truncated compression pointer");
                }
                int target = ((len & 0x3f) << 8) | (data[cursor + 1] & 0xff);
                if (target < HEADER_LENGTH || target >= limit) {
                    throw fail(cursor, "compression pointer target=" + target + " not in [" + HEADER_LENGTH + ", " + limit + ")");
                }
                if (!jumped) {
                    pos = cursor + 2;
                    jumped = true;
                }
                limit = target;
                cursor = base + target;
                continue;
            }
            if (kind != 0) {
                throw fail(cursor, "unsupported label type 0x" + Integer.toHexString(kind));
            }
            wireLength += 1 + len;
            if (wireLength > MAX_NAME_WIRE_LENGTH) {
                throw fail(cursor, "name longer than " + MAX_NAME_WIRE_LENGTH + " bytes");
            }
            if (len == 0) {
                if (!jumped) {
                    pos = cursor + 1;
                }
                return sb.toString();
            }
            if (cursor + 1 + len > end) {
                throw fail(cursor, "label length=" + len + " runs past end of message");
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            for (int i = cursor + 1; i <= cursor + len; i++) {
                char c = (char) (data[i] & 0xff);
                if (!isLabelChar(c)) {
                    throw fail(i, "unexpected label byte 0x" + Integer.toHexString(c));
                }
                sb.append(c);
            }
            cursor += 1 + len;
        }
    }

    /** 样本里出现过的标签字符：字母、数字、'-'、'_'（后者见 _dns.resolver.arpa 这类服务名）。 */
    static boolean isLabelChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    /** 报文必须正好读完，多出来的字节说明结构没读对。 */
    void expectEnd() {
        if (pos != end) {
            throw fail(pos, (end - pos) + " trailing bytes");
        }
    }

    private void require(int n) {
        if (n < 0 || pos + n > end) {
            throw fail(pos, "need " + n + " bytes, remaining " + (end - pos));
        }
    }

    IllegalArgumentException fail(String reason) {
        return fail(pos, reason);
    }

    private IllegalArgumentException fail(int at, String reason) {
        return new IllegalArgumentException(reason + " at offset " + (at - base) + ", hex=" + Hex.encodeHexString(Arrays.copyOfRange(data, base, end)));
    }
}

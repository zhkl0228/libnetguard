package com.github.netguard.vpn.udp.dns;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * 按线格式写 DNS 报文。名字支持后缀压缩：同一后缀（大小写严格一致）第二次出现时写成指针。
 */
class DnsWriter {

    private static final int MAX_POINTER_OFFSET = 0x3fff;

    private byte[] buf = new byte[512];
    private int size;
    private final Map<String, Integer> suffixOffsets = new HashMap<>();

    int position() {
        return size;
    }

    void u8(int v) {
        ensure(1);
        buf[size++] = (byte) v;
    }

    void u16(int v) {
        ensure(2);
        buf[size++] = (byte) (v >>> 8);
        buf[size++] = (byte) v;
    }

    void u32(long v) {
        u16((int) (v >>> 16));
        u16((int) v);
    }

    void bytes(byte[] b) {
        ensure(b.length);
        System.arraycopy(b, 0, buf, size, b.length);
        size += b.length;
    }

    /** 在 position 处回填一个 u16，用于先占位后补的 rdlength。 */
    void patchU16(int position, int v) {
        buf[position] = (byte) (v >>> 8);
        buf[position + 1] = (byte) v;
    }

    private void ensure(int n) {
        if (size + n > buf.length) {
            buf = Arrays.copyOf(buf, Math.max(buf.length * 2, size + n));
        }
    }

    void name(String name, boolean compress) {
        String rest = name;
        while (!rest.isEmpty()) {
            if (compress) {
                Integer offset = suffixOffsets.get(rest);
                if (offset != null) {
                    u16(0xc000 | offset);
                    return;
                }
                if (size <= MAX_POINTER_OFFSET) {
                    suffixOffsets.put(rest, size);
                }
            }
            int dot = rest.indexOf('.');
            String label = dot < 0 ? rest : rest.substring(0, dot);
            u8(label.length());
            for (int i = 0; i < label.length(); i++) {
                u8(label.charAt(i));
            }
            rest = dot < 0 ? "" : rest.substring(dot + 1);
        }
        u8(0);
    }

    byte[] toByteArray() {
        return Arrays.copyOf(buf, size);
    }

    /**
     * 校验调用方给的名字能编码：不带结尾点，标签 1..63 字节、只含 {@link DnsReader#isLabelChar}，
     * 线格式总长不超过 255。根用空串表示。
     */
    static String checkName(String name) {
        if (name.isEmpty()) {
            return name;
        }
        int wireLength = 1;
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) {
                throw new IllegalArgumentException("bad label length " + label.length() + " in name: " + name);
            }
            for (int i = 0; i < label.length(); i++) {
                if (!DnsReader.isLabelChar(label.charAt(i))) {
                    throw new IllegalArgumentException("bad label char '" + label.charAt(i) + "' in name: " + name);
                }
            }
            wireLength += 1 + label.length();
        }
        if (wireLength > 255) {
            throw new IllegalArgumentException("name longer than 255 bytes: " + name);
        }
        return name;
    }
}

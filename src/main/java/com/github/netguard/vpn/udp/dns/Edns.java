package com.github.netguard.vpn.udp.dns;

import org.apache.commons.codec.binary.Hex;

/**
 * EDNS(0) 的 OPT 伪记录（RFC 6891）。选项内容不解释，只校验 code/length 分帧后原样保留，
 * 重新编码时照搬。
 */
final class Edns {

    /** 不带 OPT 时 UDP 应答的上限，RFC 1035 §4.2.1。 */
    static final int CLASSIC_UDP_PAYLOAD_SIZE = 512;

    final int udpPayloadSize;
    /** OPT 的 TTL 字段：扩展 RCODE(8) | VERSION(8) | 标志位(16)。 */
    final long ttl;
    final byte[] options;

    private Edns(int udpPayloadSize, long ttl, byte[] options) {
        this.udpPayloadSize = udpPayloadSize;
        this.ttl = ttl;
        this.options = options;
    }

    /**
     * 读取时类型已由调用方读出并确认是 OPT，reader 停在 CLASS 字段上。
     * 样本里扩展 RCODE 和 VERSION 都是 0：扩展 RCODE 非 0 会改变 RCODE 的含义，
     * VERSION 非 0 意味着选项格式不同，都没有样本，直接抛。
     */
    static Edns read(DnsReader reader, String ownerName) {
        if (!ownerName.isEmpty()) {
            throw reader.fail("OPT owner name must be root, got " + ownerName);
        }
        int udpPayloadSize = reader.u16();
        long ttl = reader.u32();
        int extendedRcode = (int) (ttl >>> 24);
        int version = (int) ((ttl >>> 16) & 0xff);
        if (extendedRcode != 0 || version != 0) {
            throw reader.fail("OPT extended rcode=" + extendedRcode + ", version=" + version + ", expected 0/0");
        }
        int rdlength = reader.u16();
        int start = reader.position();
        while (reader.position() - start < rdlength) {
            reader.u16(); // option code
            reader.bytes(reader.u16());
        }
        int consumed = reader.position() - start;
        if (consumed != rdlength) {
            throw reader.fail("OPT options consumed " + consumed + " bytes, rdlength=" + rdlength);
        }
        return new Edns(udpPayloadSize, ttl, reader.slice(start, rdlength));
    }

    void write(DnsWriter writer) {
        writer.u8(0); // root
        writer.u16(DnsRecord.TYPE_OPT);
        writer.u16(udpPayloadSize);
        writer.u32(ttl);
        writer.u16(options.length);
        writer.bytes(options);
    }

    @Override
    public String toString() {
        return "EDNS{udp=" + udpPayloadSize + ", ttl=0x" + Long.toHexString(ttl) + (options.length == 0 ? "" : ", options=" + Hex.encodeHexString(options)) + "}";
    }
}

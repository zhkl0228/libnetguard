package com.github.netguard.vpn.udp.dns;

import org.apache.commons.codec.binary.Hex;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * 应答里的一条资源记录（class 恒为 IN）。
 * <p>
 * 只认抓到过样本的类型：A、AAAA、CNAME、SOA、HTTPS，其余类型在解码时直接抛异常。
 * 这不只是保守：CNAME/SOA 这类老类型的 rdata 里有压缩指针，不认识类型就把 rdata
 * 当不透明字节搬到新报文里，指针偏移会全部错位。所以 rdata 一律存成去压缩后的
 * 规范形式，编码时再按类型重新压缩。
 */
public final class DnsRecord {

    public static final int TYPE_A = 1;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_HTTPS = 65;
    static final int TYPE_OPT = 41;

    static final int CLASS_IN = 1;

    private final String name;
    private final int type;
    private final long ttl;
    private final byte[] rdata;

    private DnsRecord(String name, int type, long ttl, byte[] rdata) {
        if (ttl < 0 || ttl > 0xffffffffL) {
            throw new IllegalArgumentException("ttl out of range: " + ttl);
        }
        this.name = DnsWriter.checkName(name);
        this.type = type;
        this.ttl = ttl;
        this.rdata = rdata;
    }

    public static DnsRecord a(String name, long ttl, Inet4Address address) {
        return new DnsRecord(name, TYPE_A, ttl, address.getAddress());
    }

    public static DnsRecord aaaa(String name, long ttl, Inet6Address address) {
        return new DnsRecord(name, TYPE_AAAA, ttl, address.getAddress());
    }

    public static DnsRecord cname(String name, long ttl, String target) {
        DnsWriter writer = new DnsWriter();
        writer.name(DnsWriter.checkName(target), false);
        return new DnsRecord(name, TYPE_CNAME, ttl, writer.toByteArray());
    }

    /** 不带结尾点，根为空串。 */
    public String getName() {
        return name;
    }

    public int getType() {
        return type;
    }

    public long getTtl() {
        return ttl;
    }

    /** 去压缩后的规范 rdata。 */
    public byte[] getRdata() {
        return rdata.clone();
    }

    /** A/AAAA 的地址。 */
    public InetAddress getAddress() {
        if (type != TYPE_A && type != TYPE_AAAA) {
            throw new IllegalStateException("not an address record: " + this);
        }
        try {
            return InetAddress.getByAddress(name, rdata);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /** CNAME 的目标名。 */
    public String getTarget() {
        if (type != TYPE_CNAME) {
            throw new IllegalStateException("not a CNAME record: " + this);
        }
        return new DnsReader(rdata, 0, rdata.length).name(false);
    }

    /**
     * 读一条非 OPT 记录。OPT 由调用方先看类型再交给 {@link Edns#read}，这里遇到会抛。
     */
    static DnsRecord read(DnsReader reader, String section) {
        String name = reader.name(true);
        int type = reader.u16();
        int dnsClass = reader.u16();
        long ttl = reader.u32();
        int rdlength = reader.u16();
        if (dnsClass != CLASS_IN) {
            throw reader.fail(section + " record " + name + " type=" + type + " has class=" + dnsClass + ", expected IN");
        }
        int rdataStart = reader.position();
        if (rdlength > reader.remaining()) {
            throw reader.fail(section + " record " + name + " type=" + type + " rdlength=" + rdlength + " exceeds remaining " + reader.remaining());
        }
        byte[] rdata;
        switch (type) {
            case TYPE_A:
            case TYPE_AAAA: {
                int expected = type == TYPE_A ? 4 : 16;
                if (rdlength != expected) {
                    throw reader.fail(section + " " + typeName(type) + " record " + name + " rdlength=" + rdlength + ", expected " + expected);
                }
                rdata = reader.bytes(rdlength);
                break;
            }
            case TYPE_CNAME: {
                DnsWriter canonical = new DnsWriter();
                canonical.name(reader.name(true), false);
                rdata = canonical.toByteArray();
                break;
            }
            case TYPE_SOA: {
                DnsWriter canonical = new DnsWriter();
                canonical.name(reader.name(true), false); // MNAME
                canonical.name(reader.name(true), false); // RNAME
                canonical.bytes(reader.bytes(20)); // SERIAL REFRESH RETRY EXPIRE MINIMUM
                rdata = canonical.toByteArray();
                break;
            }
            case TYPE_HTTPS: {
                // RFC 9460：SvcPriority、TargetName（禁止压缩），然后是 key/length/value 序列。
                // 内容不解释，只校验分帧，原样保留。
                reader.u16();
                reader.name(false);
                while (reader.position() - rdataStart < rdlength) {
                    reader.u16();
                    reader.bytes(reader.u16());
                }
                int consumed = reader.position() - rdataStart;
                if (consumed != rdlength) {
                    throw reader.fail(section + " HTTPS record " + name + " consumed " + consumed + " bytes, rdlength=" + rdlength);
                }
                return new DnsRecord(name, type, ttl, reader.slice(rdataStart, rdlength));
            }
            default:
                throw reader.fail(section + " record " + name + " has unsupported type=" + type + ", rdlength=" + rdlength);
        }
        int consumed = reader.position() - rdataStart;
        if (consumed != rdlength) {
            throw reader.fail(section + " " + typeName(type) + " record " + name + " consumed " + consumed + " bytes, rdlength=" + rdlength);
        }
        return new DnsRecord(name, type, ttl, rdata);
    }

    void write(DnsWriter writer) {
        writer.name(name, true);
        writer.u16(type);
        writer.u16(CLASS_IN);
        writer.u32(ttl);
        int rdlengthPosition = writer.position();
        writer.u16(0);
        int rdataStart = writer.position();
        DnsReader canonical = new DnsReader(rdata, 0, rdata.length);
        switch (type) {
            case TYPE_CNAME:
                writer.name(canonical.name(false), true);
                break;
            case TYPE_SOA:
                writer.name(canonical.name(false), true);
                writer.name(canonical.name(false), true);
                writer.bytes(canonical.bytes(20));
                break;
            default:
                writer.bytes(rdata);
                break;
        }
        writer.patchU16(rdlengthPosition, writer.position() - rdataStart);
    }

    static String typeName(int type) {
        switch (type) {
            case TYPE_A:
                return "A";
            case TYPE_CNAME:
                return "CNAME";
            case TYPE_SOA:
                return "SOA";
            case TYPE_AAAA:
                return "AAAA";
            case TYPE_OPT:
                return "OPT";
            case TYPE_HTTPS:
                return "HTTPS";
            default:
                return "TYPE" + type; // RFC 3597 的未知类型写法，仅用于显示
        }
    }

    @Override
    public String toString() {
        String value;
        switch (type) {
            case TYPE_A:
            case TYPE_AAAA:
                value = getAddress().getHostAddress();
                break;
            case TYPE_CNAME:
                value = getTarget();
                break;
            default:
                value = Hex.encodeHexString(rdata);
                break;
        }
        return name + " " + ttl + " " + typeName(type) + " " + value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DnsRecord)) return false;
        DnsRecord that = (DnsRecord) o;
        return type == that.type && ttl == that.ttl && name.equals(that.name) && Arrays.equals(rdata, that.rdata);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * name.hashCode() + type) + Arrays.hashCode(rdata);
    }
}

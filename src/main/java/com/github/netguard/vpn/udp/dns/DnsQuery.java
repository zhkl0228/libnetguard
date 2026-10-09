package com.github.netguard.vpn.udp.dns;

import java.util.Collections;

/**
 * 客户端发出的一条 DNS 查询。
 * <p>
 * 样本（dig、nslookup）都是：一个问题，应答/授权段为空，附加段要么为空、要么只有一条 OPT。
 * 不符合的一律抛异常——这是解码型方法，调用方已经认定这是 DNS 流量（目的端口 53）。
 */
public final class DnsQuery {

    static final int FLAG_QR = 0x8000;
    static final int OPCODE_MASK = 0x7800;
    static final int FLAG_TC = 0x0200;
    static final int FLAG_RD = 0x0100;
    static final int FLAG_RA = 0x0080;
    static final int FLAG_Z = 0x0040;
    static final int FLAG_AD = 0x0020;
    static final int FLAG_CD = 0x0010;
    static final int RCODE_MASK = 0x000f;

    /**
     * 查询里可以出现的标志位。RD/AD/CD 只是透传给上游的请求意图，不影响报文结构和我们的解读；
     * 其余位（QR、OPCODE、AA、TC、RA、Z、RCODE）在查询里都应为 0，非 0 说明这不是我们见过的普通查询。
     */
    private static final int ALLOWED_QUERY_FLAGS = FLAG_RD | FLAG_AD | FLAG_CD;

    private final int id;
    private final int flags;
    private final DnsQuestion question;
    private final Edns edns;

    private DnsQuery(int id, int flags, DnsQuestion question, Edns edns) {
        this.id = id;
        this.flags = flags;
        this.question = question;
        this.edns = edns;
    }

    public static DnsQuery decode(byte[] data, int offset, int length) {
        DnsReader reader = new DnsReader(data, offset, length);
        int id = reader.u16();
        int flags = reader.u16();
        int qdcount = reader.u16();
        int ancount = reader.u16();
        int nscount = reader.u16();
        int arcount = reader.u16();
        if ((flags & ~ALLOWED_QUERY_FLAGS) != 0) {
            throw reader.fail("query flags=0x" + Integer.toHexString(flags) + " has bits outside RD/AD/CD");
        }
        if (qdcount != 1 || ancount != 0 || nscount != 0 || arcount > 1) {
            throw reader.fail("query counts qd=" + qdcount + ", an=" + ancount + ", ns=" + nscount + ", ar=" + arcount + ", expected 1/0/0/0..1");
        }
        DnsQuestion question = DnsQuestion.read(reader);
        Edns edns = null;
        if (arcount == 1) {
            String ownerName = reader.name(false);
            int type = reader.u16();
            if (type != DnsRecord.TYPE_OPT) {
                throw reader.fail("query additional record type=" + type + ", expected OPT");
            }
            edns = Edns.read(reader, ownerName);
        }
        reader.expectEnd();
        return new DnsQuery(id, flags, question, edns);
    }

    public int getId() {
        return id;
    }

    public DnsQuestion getQuestion() {
        return question;
    }

    /** 等同 {@code getQuestion().getName()}。 */
    public String getName() {
        return question.getName();
    }

    /** 等同 {@code getQuestion().getType()}，取值见 {@link DnsRecord} 的 TYPE_ 常量。 */
    public int getType() {
        return question.getType();
    }

    /** 客户端能收的最大 UDP 应答：带 OPT 取其声明值（不低于 512），否则 512。 */
    int maxResponseSize() {
        return edns == null ? Edns.CLASSIC_UDP_PAYLOAD_SIZE : Math.max(Edns.CLASSIC_UDP_PAYLOAD_SIZE, edns.udpPayloadSize);
    }

    /**
     * 构造一条空的应答：ID 和问题段照抄，QR/RA 置位，RD 照抄，RCODE 为 NOERROR，不带 OPT。
     * 往 {@link DnsResponse#getAnswers()} 里加记录即可。
     */
    public DnsResponse reply() {
        return new DnsResponse(this, FLAG_QR | (flags & FLAG_RD) | FLAG_RA, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), null);
    }

    @Override
    public String toString() {
        return "DnsQuery{id=" + id + ", flags=0x" + Integer.toHexString(flags) + ", " + question + (edns == null ? "" : ", " + edns) + "}";
    }
}

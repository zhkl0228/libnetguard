package com.github.netguard.vpn.udp.dns;

import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;

/**
 * 一条 DNS 应答：上游发回的（{@link #decode}），或者由 {@link DnsQuery#reply()} 新建的。
 * 三个记录列表都可以直接改，改完由 {@link #encode()} 重新编码。
 */
public final class DnsResponse {

    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_NXDOMAIN = 3;

    private final DnsQuery query;
    private int flags;
    private final List<DnsRecord> answers;
    private final List<DnsRecord> authorities;
    private final List<DnsRecord> additionals;
    private final Edns edns;

    DnsResponse(DnsQuery query, int flags, List<DnsRecord> answers, List<DnsRecord> authorities, List<DnsRecord> additionals, Edns edns) {
        this.query = query;
        this.flags = flags;
        this.answers = new ArrayList<>(answers);
        this.authorities = new ArrayList<>(authorities);
        this.additionals = new ArrayList<>(additionals);
        this.edns = edns;
    }

    /**
     * 解码上游应答，并确认它回答的是 pendingQuery 按 ID 找到的那条查询（问题段必须一致）。
     *
     * @param pendingQuery 按应答 ID 取出对应的查询；找不到返回 null，此时抛异常
     */
    public static DnsResponse decode(byte[] data, int offset, int length, IntFunction<DnsQuery> pendingQuery) {
        DnsReader reader = new DnsReader(data, offset, length);
        int id = reader.u16();
        int flags = reader.u16();
        int qdcount = reader.u16();
        int ancount = reader.u16();
        int nscount = reader.u16();
        int arcount = reader.u16();
        if ((flags & DnsQuery.FLAG_QR) == 0 || (flags & (DnsQuery.OPCODE_MASK | DnsQuery.FLAG_Z)) != 0) {
            throw reader.fail("response flags=0x" + Integer.toHexString(flags) + ", expected QR=1, OPCODE=0, Z=0");
        }
        if ((flags & DnsQuery.FLAG_TC) != 0) {
            throw reader.fail("truncated response (TC=1)");
        }
        if (qdcount != 1) {
            throw reader.fail("response qdcount=" + qdcount + ", expected 1");
        }
        DnsQuery query = pendingQuery.apply(id);
        if (query == null) {
            throw reader.fail("response id=" + id + " matches no pending query");
        }
        DnsQuestion question = DnsQuestion.read(reader);
        if (!question.equals(query.getQuestion())) {
            throw reader.fail("response question " + question + " does not match query " + query);
        }
        List<DnsRecord> answers = readSection(reader, "answer", ancount);
        List<DnsRecord> authorities = readSection(reader, "authority", nscount);
        List<DnsRecord> additionals = new ArrayList<>(arcount);
        Edns edns = null;
        for (int i = 0; i < arcount; i++) {
            int recordStart = reader.position();
            String ownerName = reader.name(true);
            int type = reader.u16();
            if (type == DnsRecord.TYPE_OPT) {
                if (edns != null) {
                    throw reader.fail("more than one OPT record");
                }
                edns = Edns.read(reader, ownerName);
            } else {
                additionals.add(DnsRecord.read(reader.rewind(recordStart), "additional"));
            }
        }
        reader.expectEnd();
        return new DnsResponse(query, flags, answers, authorities, additionals, edns);
    }

    private static List<DnsRecord> readSection(DnsReader reader, String section, int count) {
        List<DnsRecord> records = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            records.add(DnsRecord.read(reader, section));
        }
        return records;
    }

    /**
     * 编码成发回给客户端的字节。ID 和问题段取自所属查询；结果不能超过客户端能收的大小——
     * 超了就得截断并置 TC，这条路径没有样本，直接抛。
     */
    public byte[] encode() {
        DnsWriter writer = new DnsWriter();
        writer.u16(query.getId());
        writer.u16(flags);
        writer.u16(1);
        writer.u16(answers.size());
        writer.u16(authorities.size());
        writer.u16(additionals.size() + (edns == null ? 0 : 1));
        query.getQuestion().write(writer);
        for (DnsRecord record : answers) {
            record.write(writer);
        }
        for (DnsRecord record : authorities) {
            record.write(writer);
        }
        for (DnsRecord record : additionals) {
            record.write(writer);
        }
        if (edns != null) {
            edns.write(writer);
        }
        byte[] data = writer.toByteArray();
        if (data.length > query.maxResponseSize()) {
            throw new IllegalStateException("encoded response " + data.length + " bytes exceeds client limit " + query.maxResponseSize() + ": " + this);
        }
        return data;
    }

    /** 这条应答所回答的查询。 */
    public DnsQuery getQuery() {
        return query;
    }

    public int getRcode() {
        return flags & DnsQuery.RCODE_MASK;
    }

    public void setRcode(int rcode) {
        if ((rcode & ~DnsQuery.RCODE_MASK) != 0) {
            throw new IllegalArgumentException("rcode out of range: " + rcode);
        }
        flags = (flags & ~DnsQuery.RCODE_MASK) | rcode;
    }

    /** 可修改。 */
    public List<DnsRecord> getAnswers() {
        return answers;
    }

    /** 可修改。 */
    public List<DnsRecord> getAuthorities() {
        return authorities;
    }

    /** 可修改，不含 OPT。 */
    public List<DnsRecord> getAdditionals() {
        return additionals;
    }

    @Override
    public String toString() {
        return "DnsResponse{id=" + query.getId() + ", flags=0x" + Integer.toHexString(flags) + ", rcode=" + getRcode() + ", " + query.getQuestion() +
                ", answers=" + answers +
                (authorities.isEmpty() ? "" : ", authorities=" + authorities) +
                (additionals.isEmpty() ? "" : ", additionals=" + additionals) +
                (edns == null ? "" : ", " + edns) + "}";
    }
}

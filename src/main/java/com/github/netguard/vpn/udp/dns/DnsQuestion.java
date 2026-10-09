package com.github.netguard.vpn.udp.dns;

/**
 * 问题段的一条：名字、类型、class（样本里都是 IN）。
 */
public final class DnsQuestion {

    private final String name;
    private final int type;

    DnsQuestion(String name, int type) {
        this.name = name;
        this.type = type;
    }

    /**
     * 问题段里不会有压缩指针：它紧跟在报文头后面，前面没有可以指向的名字。
     */
    static DnsQuestion read(DnsReader reader) {
        String name = reader.name(false);
        int type = reader.u16();
        int dnsClass = reader.u16();
        if (dnsClass != DnsRecord.CLASS_IN) {
            throw reader.fail("question " + name + " type=" + type + " has class=" + dnsClass + ", expected IN");
        }
        return new DnsQuestion(name, type);
    }

    void write(DnsWriter writer) {
        writer.name(name, true);
        writer.u16(type);
        writer.u16(DnsRecord.CLASS_IN);
    }

    /** 不带结尾点，大小写保持报文原样（可能被 0x20 编码打乱）。 */
    public String getName() {
        return name;
    }

    public int getType() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DnsQuestion)) return false;
        DnsQuestion that = (DnsQuestion) o;
        return type == that.type && name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return 31 * name.hashCode() + type;
    }

    @Override
    public String toString() {
        return name + " " + DnsRecord.typeName(type);
    }
}

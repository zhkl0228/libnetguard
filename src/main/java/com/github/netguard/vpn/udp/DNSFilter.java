package com.github.netguard.vpn.udp;

import com.github.netguard.vpn.udp.dns.DnsQuery;
import com.github.netguard.vpn.udp.dns.DnsResponse;

public interface DNSFilter {

    /**
     * @return 非 null 时直接把它回给客户端，查询不再发往上游；一般用 {@link DnsQuery#reply()} 构造
     */
    DnsResponse cancelDnsQuery(DnsQuery dnsQuery);

    /**
     * @param dnsResponse 上游应答，可以就地修改后返回
     * @return 非 null 时用它代替上游应答发回客户端；null 则原样转发上游字节
     */
    DnsResponse filterDnsResponse(DnsQuery dnsQuery, DnsResponse dnsResponse);

}

package com.github.netguard.vpn.udp;

import org.xbill.DNS.Message;

public interface DNSFilter {

    Message cancelDnsQuery(Message dnsQuery);

    Message filterDnsResponse(Message dnsQuery, Message dnsResponse);

}

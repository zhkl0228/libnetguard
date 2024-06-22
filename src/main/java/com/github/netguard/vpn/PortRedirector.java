package com.github.netguard.vpn;

import eu.faircode.netguard.Allowed;

public interface PortRedirector {

    Allowed redirectTcp(String saddr, int sport, String daddr, int dport);
    Allowed redirectUdp(String saddr, int sport, String daddr, int dport);

}

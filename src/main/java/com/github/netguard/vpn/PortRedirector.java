package com.github.netguard.vpn;

import eu.faircode.netguard.Allowed;

public interface PortRedirector {

    Allowed redirect(String ip, int port);

}

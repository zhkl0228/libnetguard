package com.github.netguard;

import java.util.List;

public abstract class ProxyVpn implements Runnable {

    protected final List<ProxyVpn> clients;

    protected ProxyVpn(List<ProxyVpn> clients) {
        this.clients = clients;
    }

    protected abstract void stop();

}

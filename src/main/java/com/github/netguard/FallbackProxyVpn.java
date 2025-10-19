package com.github.netguard;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

public abstract class FallbackProxyVpn extends ProxyVpn {

    protected final Socket socket;

    public FallbackProxyVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert) {
        super(clients, rootCert);
        this.socket = socket;
    }

    @Override
    protected final void stop() {
        IoUtil.close(socket);
    }

    @Override
    public ClientOS getClientOS() {
        return ClientOS.Fallback;
    }

    @Override
    public final InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }
}

package com.github.netguard;

import com.github.netguard.proxy.HttpProxyVpn;
import com.github.netguard.proxy.HttpsProxyVpn;
import com.github.netguard.proxy.SocksProxyVpn;
import com.github.netguard.proxy.TrojanProxyVpn;
import com.github.netguard.sslvpn.SSLVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.util.List;

public abstract class ProxyVpnFactory {

    private static final Logger log = LoggerFactory.getLogger(ProxyVpnFactory.class);

    static class VpnFactory extends ProxyVpnFactory {
        private final int os;
        private final boolean useNetGuardCore;
        VpnFactory(int os, boolean useNetGuardCore) {
            this.os = os;
            this.useNetGuardCore = useNetGuardCore;
        }
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) throws IOException {
            ProxyVpn vpn = null;
            if (useNetGuardCore) {
                try {
                    vpn = new ServiceSinkhole(socket, clients, rootCert, os);
                } catch (UnsatisfiedLinkError e) {
                    log.debug("init ServiceSinkhole", e);
                }
            }
            if (vpn == null) {
                vpn = new ProxyVpnRunnable(socket, clients, rootCert, os);
            }
            return vpn;
        }
    }

    static class SSLVpnFactory extends ProxyVpnFactory {
        private final int serverPort;
        private final ClientHelloRecord clientHelloRecord;
        SSLVpnFactory(int serverPort, ClientHelloRecord clientHelloRecord) {
            this.serverPort = serverPort;
            this.clientHelloRecord = clientHelloRecord;
        }
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
            return SSLVpn.newSSLVpn(socket, clients, rootCert, inputStream, serverPort, clientHelloRecord);
        }
    }

    static class SocksProxyFactory extends ProxyVpnFactory {
        private final ClientOS clientOS;
        SocksProxyFactory(ClientOS clientOS) {
            this.clientOS = clientOS;
        }
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
            return new SocksProxyVpn(socket, clients, rootCert, inputStream, clientOS);
        }
    }

    static class HttpsProxyFactory extends ProxyVpnFactory {
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
            return new HttpsProxyVpn(socket, clients, rootCert, inputStream);
        }
    }

    static class HttpProxyFactory extends ProxyVpnFactory {
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
            return new HttpProxyVpn(socket, clients, rootCert, inputStream);
        }
    }

    static class TrojanProxyFactory extends ProxyVpnFactory {
        @Override
        protected ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
            return new TrojanProxyVpn(socket, clients, rootCert, inputStream);
        }
    }

    protected abstract ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) throws IOException;

}

package com.github.netguard;

import com.github.netguard.socks.SocksVpn;
import com.github.netguard.sslvpn.SSLVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.List;

abstract class ProxyVpnFactory {

    private static final Logger log = LoggerFactory.getLogger(ProxyVpnFactory.class);

    static class VpnFactory extends ProxyVpnFactory {
        private final int os;
        private final boolean useNetGuardCore;
        VpnFactory(int os, boolean useNetGuardCore) {
            this.os = os;
            this.useNetGuardCore = useNetGuardCore;
        }
        @Override
        ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert) throws IOException {
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
        private final InputStream inputStream;
        private final int serverPort;
        private final ClientHelloRecord clientHelloRecord;
        SSLVpnFactory(InputStream inputStream, int serverPort, ClientHelloRecord clientHelloRecord) {
            this.inputStream = inputStream;
            this.serverPort = serverPort;
            this.clientHelloRecord = clientHelloRecord;
        }
        @Override
        ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert) {
            return SSLVpn.newSSLVpn(socket, clients, rootCert, inputStream, serverPort, clientHelloRecord);
        }
    }

    static class SocksFactory extends ProxyVpnFactory {
        private final ClientOS clientOS;
        SocksFactory(ClientOS clientOS) {
            this.clientOS = clientOS;
        }
        @Override
        ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert) {
            return new SocksVpn(socket, clients, rootCert, clientOS);
        }
    }

    abstract ProxyVpn newVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert) throws IOException;

}

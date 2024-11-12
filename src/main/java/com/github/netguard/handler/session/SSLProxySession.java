package com.github.netguard.handler.session;

import com.github.netguard.vpn.Vpn;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionImpl;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpState;

import java.util.Collection;

public class SSLProxySession extends TcpSessionImpl implements TcpSession {

    private final String hostName;
    private final Collection<String> applicationProtocols;
    private final String selectedApplicationProtocol;
    private final String application;

    public SSLProxySession(TcpSessionKey key, String hostName, Collection<String> applicationProtocols, String selectedApplicationProtocol, String application) {
        super(null);
        this.hostName = hostName;
        this.applicationProtocols = applicationProtocols;
        this.selectedApplicationProtocol = selectedApplicationProtocol;
        this.application = application;

        this.setKey(key);
    }

    @Override
    public Protocol getProtocol() {
        if (Vpn.HTTP2_PROTOCOL.equals(selectedApplicationProtocol)) {
            return Protocol.HTTP2;
        } else if ("http/1.1".equals(selectedApplicationProtocol)) {
            return Protocol.HTTP;
        } else if (selectedApplicationProtocol == null || selectedApplicationProtocol.isEmpty()) {
            if (applicationProtocols != null && applicationProtocols.contains("http/1.1")) {
                return Protocol.HTTP;
            }
        }
        return Protocol.SSL;
    }

    @Override
    public TcpState getClientState() {
        return TcpState.ESTABLISHED;
    }

    @Override
    public TcpState getServerState() {
        return TcpState.ESTABLISHED;
    }

    @Override
    public String[] getApplicationProtocols() {
        return applicationProtocols == null ? null : applicationProtocols.toArray(new String[0]);
    }

    @Override
    public String getSelectedApplicationProtocol() {
        return selectedApplicationProtocol;
    }

    @Override
    public String getApplication() {
        return application;
    }

    @Override
    public String toString() {
        return getKey() + "[" + hostName + "]";
    }
}

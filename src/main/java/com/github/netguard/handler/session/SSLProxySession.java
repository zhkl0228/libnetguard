package com.github.netguard.handler.session;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionImpl;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpState;

public class SSLProxySession extends TcpSessionImpl implements TcpSession {

    private final String applicationProtocol;

    public SSLProxySession(TcpSessionKey key, String applicationProtocol) {
        super(null);
        this.applicationProtocol = applicationProtocol;

        this.setKey(key);
    }

    @Override
    public Protocol getProtocol() {
        if ("h2".equals(applicationProtocol)) {
            return Protocol.HTTP2;
        } else if ("http/1.1".equals(applicationProtocol)) {
            return Protocol.HTTP;
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
}

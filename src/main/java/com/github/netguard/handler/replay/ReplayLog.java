package com.github.netguard.handler.replay;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.tcp.TcpSessionImpl;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKeyImpl;
import org.krakenapps.pcap.decoder.tcp.TcpState;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Date;

class ReplayLog {

    private static final Logger log = LoggerFactory.getLogger(ReplayLog.class);

    public static ReplayLog createLog(TcpSessionKey key, ReplayEvent event) {
        return createLog(key, event, null);
    }

    public static ReplayLog createLog(TcpSessionKey key, ReplayEvent event, byte[] data) {
        ReplayLog log = new ReplayLog(event, data);
        log.clientIp = key.getClientIp().getHostAddress();
        log.clientPort = key.getClientPort();
        log.serverIp = key.getServerIp().getHostAddress();
        log.serverPort = key.getServerPort();
        return log;
    }

    public Protocol protocol;

    public ReplayLog setProtocol(Protocol protocol) {
        this.protocol = protocol;
        return this;
    }

    void replay(HttpDecoder httpDecoder) {
        if (event == null) {
            throw new IllegalStateException("event is null");
        }
        ThreadLocal<Date> threadLocal = Replay.replayLogDate;
        if (threadLocal != null && timestamp > 0) {
            threadLocal.set(new Date(timestamp));
        }
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            switch (event) {
                case TcpConnect: {
                    TcpSessionImpl session = new TcpSessionImpl(null) {
                        @Override
                        public String getApplication() {
                            return "Replay";
                        }
                    };
                    session.registerProtocol(protocol);
                    session.setKey(key);
                    session.setClientState(TcpState.ESTABLISHED);
                    session.setServerState(TcpState.ESTABLISHED);
                    httpDecoder.onEstablish(session);
                    break;
                    }
                case TcpSend:
                    httpDecoder.handleTx(key, new ChainBuffer(data));
                    break;
                case TcpReceive:
                    httpDecoder.handleRx(key, new ChainBuffer(data));
                    break;
                case TcpClose:
                    httpDecoder.onFinish(key);
                    break;
                default:
                    throw new IllegalStateException("unexpected event: " + event);
            }
        } catch (Exception e) {
            log.warn("replay", e);
        }
    }

    public String clientIp, serverIp;
    public int clientPort, serverPort;
    public ReplayEvent event;
    public byte[] data;
    public long timestamp;

    @SuppressWarnings("unused")
    public ReplayLog() {
    }

    private ReplayLog(ReplayEvent event, byte[] data) {
        this.event = event;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
    }

    @Override
    public String toString() {
        return String.format("%s %s:%d => %s:%d", event, clientIp, clientPort, serverIp, serverPort);
    }
}

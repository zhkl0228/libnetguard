package com.github.netguard.handler.replay;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Replay implements TcpProcessor {

    private static final Logger log = LoggerFactory.getLogger(Replay.class);

    public abstract void doReplay(HttpDecoder httpDecoder);

    public abstract void writeTcpConnect(TcpSessionKey key, Protocol protocol);
    public abstract void writeTcpClose(TcpSessionKey key);
    public abstract void writeTcpSend(TcpSessionKey key, byte[] data);
    public abstract void writeTcpReceive(TcpSessionKey key, byte[] data);

    @Override
    public final void onReset(TcpSessionKey key) {
        log.debug("onReset: key={}", key);
    }

    @Override
    public final void onFinish(TcpSessionKey key) {
        try {
            writeTcpClose(key);
        } catch (Exception e) {
            log.warn("onFinish", e);
        }
    }

    @Override
    public final boolean onEstablish(TcpSession session) {
        log.debug("onEstablish: session={}", session);
        try {
            writeTcpConnect(session.getKey(), session.getProtocol());
        } catch(Exception e) {
            log.warn("onEstablish", e);
        }
        return false;
    }

    @Override
    public final void handleTx(TcpSessionKey session, Buffer data) {
        try {
            log.debug("handleTx: session={}", session);
            data.mark();
            byte[] buffer = new byte[data.readableBytes()];
            data.gets(buffer);
            writeTcpSend(session, buffer);
        } catch (Exception e) {
            log.warn("handleTx", e);
        } finally {
            data.reset();
        }
    }

    @Override
    public final void handleRx(TcpSessionKey session, Buffer data) {
        try {
            log.debug("handleRx: session={}", session);
            data.mark();
            byte[] buffer = new byte[data.readableBytes()];
            data.gets(buffer);
            writeTcpReceive(session, buffer);
        } catch (Exception e) {
            log.warn("handleRx", e);
        } finally {
            data.reset();
        }
    }
}

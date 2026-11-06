package com.github.netguard.vpn.tcp.ws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 一条被 MITM 的 WebSocket 连接的会话信息。
 */
public class WebSocketSession {

    private static final Logger log = LoggerFactory.getLogger(WebSocketSession.class);

    private final InetSocketAddress client;
    private final InetSocketAddress server;
    private final String hostName;

    // 由 server 端 101 响应的 Sec-WebSocket-Extensions 解析得到
    volatile boolean permessageDeflate;
    volatile boolean serverNoContextTakeover;
    volatile boolean clientNoContextTakeover;
    volatile boolean established;

    // HTTP/1.1 path: set by the client-to-server side when the connection starts with an upgrade request
    volatile boolean upgradeRequested;
    // HTTP/1.1 path: counted down by the server-to-client side once the first response has decided whether this is a WebSocket
    final CountDownLatch handshakeDone = new CountDownLatch(1);

    private static final int NEW = 0;
    private static final int CONNECTED = 1;
    private static final int CLOSE_PENDING = 2;
    private static final int CLOSED = 3;

    private final AtomicInteger state = new AtomicInteger(NEW);
    private final AtomicInteger endedStreams = new AtomicInteger();

    public WebSocketSession(InetSocketAddress client, InetSocketAddress server, String hostName) {
        this.client = client;
        this.server = server;
        this.hostName = hostName;
    }

    public InetSocketAddress getClient() {
        return client;
    }

    public InetSocketAddress getServer() {
        return server;
    }

    public String getHostName() {
        return hostName;
    }

    public boolean isPermessageDeflate() {
        return permessageDeflate;
    }

    public boolean isEstablished() {
        return established;
    }

    /**
     * The handshake has completed: marks the session established and calls {@link WebSocketFilter#onConnected}.
     * If the session was closed from the other direction while that ran, {@link WebSocketFilter#onClosed} follows it.
     */
    public void connect(WebSocketFilter filter, WebSocketInjector injector) {
        established = true;
        try {
            filter.onConnected(this, injector);
        } catch (Throwable t) {
            log.warn("webSocket onConnected failed: session={}", this, t);
        }
        if (!state.compareAndSet(NEW, CONNECTED)) {
            // close() was called while onConnected ran, and left the onClosed call to us
            state.set(CLOSED);
            notifyClosed(filter);
        }
    }

    /**
     * One direction has finished (its read side reached EOF, or HTTP/2 END_STREAM); the session closes once both have.
     */
    public void endStream(WebSocketFilter filter) {
        if (endedStreams.incrementAndGet() == 2) {
            close(filter);
        }
    }

    /**
     * Both directions are gone at once (HTTP/2 RST_STREAM, or the connection ended). Calls
     * {@link WebSocketFilter#onClosed} exactly once and only after {@link WebSocketFilter#onConnected};
     * a session that never connected gets no callback. Safe to call from either direction, any number of times.
     */
    public void close(WebSocketFilter filter) {
        if (state.compareAndSet(CONNECTED, CLOSED)) {
            notifyClosed(filter);
        } else {
            // Not connected yet: if connect() comes later, it calls onClosed right after onConnected
            state.compareAndSet(NEW, CLOSE_PENDING);
        }
    }

    private void notifyClosed(WebSocketFilter filter) {
        try {
            filter.onClosed(this);
        } catch (Throwable t) {
            log.warn("webSocket onClosed failed: session={}", this, t);
        }
    }

    @Override
    public String toString() {
        return "WebSocketSession{" + client + " => " + server + " (" + hostName + "), deflate=" + permessageDeflate + '}';
    }
}

package com.github.netguard.vpn.udp;

import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class QuicProxy implements ApplicationProtocolConnectionFactory, ApplicationProtocolConnection {

    private static final Logger log = LoggerFactory.getLogger(QuicProxy.class);
    private final QuicClientConnection connection;

    QuicProxy(QuicClientConnection connection) {
        this.connection = connection;
    }

    @Override
    public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
        log.debug("createConnection protocol={}, quicConnection={}", protocol, quicConnection);
        return this;
    }

    @Override
    public void acceptPeerInitiatedStream(QuicStream serverStream) {
        log.debug("acceptPeerInitiatedStream serverStream={}", serverStream);
        Thread thread = new Thread(new AcceptPeerInitiatedStream(serverStream), "acceptPeerInitiatedStream");
        thread.setDaemon(true);
        thread.start();
    }

    private class AcceptPeerInitiatedStream implements Runnable {
        private final QuicStream serverStream;

        AcceptPeerInitiatedStream(QuicStream serverStream) {
            this.serverStream = serverStream;
        }

        @Override
        public void run() {
            try {
                boolean bidirectional = serverStream.isBidirectional();
                QuicStream clientStream = connection.createStream(bidirectional);
                log.debug("createStream bidirectional={}, clientStream={}, serverStream={}", bidirectional, clientStream, serverStream);
                StreamForward.forward(clientStream, serverStream, bidirectional);
            } catch (Exception e) {
                log.warn("run", e);
            }
        }
    }
}

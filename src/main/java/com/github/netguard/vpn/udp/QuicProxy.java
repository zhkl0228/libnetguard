package com.github.netguard.vpn.udp;

import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicConstants;
import net.luminis.quic.QuicStream;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;

class QuicProxy implements ApplicationProtocolConnectionFactory, ApplicationProtocolConnection {

    private static final Logger log = LoggerFactory.getLogger(QuicProxy.class);
    private final ExecutorService executorService;
    private final QuicClientConnection connection;

    QuicProxy(ExecutorService executorService, QuicClientConnection connection) {
        this.executorService = executorService;
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
        executorService.submit(new AcceptPeerInitiatedStream(serverStream));
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
                StreamForward.forward(clientStream, serverStream, bidirectional, executorService);
            } catch (Exception e) {
                log.debug("createStream", e);
                serverStream.resetStream(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value);
            }
        }
    }
}

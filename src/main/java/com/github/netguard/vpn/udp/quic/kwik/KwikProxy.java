package com.github.netguard.vpn.udp.quic.kwik;

import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.tcp.h2.Http2SessionKey;
import com.github.netguard.vpn.udp.quic.QuicStreamForward;
import com.github.netguard.vpn.udp.quic.QuicStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;

import java.util.concurrent.ExecutorService;

class KwikProxy implements ApplicationProtocolConnectionFactory {

    private static final Logger log = LoggerFactory.getLogger(KwikProxy.class);
    private final ExecutorService executorService;
    private final QuicClientConnection clientConnection;
    private final Http2Session session;
    private final Http2Filter http2Filter;

    KwikProxy(ExecutorService executorService, QuicClientConnection clientConnection, Http2Session session, Http2Filter http2Filter) {
        this.executorService = executorService;
        this.clientConnection = clientConnection;
        this.session = session;
        this.http2Filter = http2Filter;
    }

    @Override
    public ApplicationProtocolConnection createConnection(String protocol, final QuicConnection serverConnection) {
        log.debug("createConnection protocol={}, serverConnection={}", protocol, serverConnection);
        return new ApplicationProtocolConnection() {
            @Override
            public void acceptPeerInitiatedStream(tech.kwik.core.QuicStream serverStream) {
                log.debug("acceptPeerInitiatedStream serverStream={}", serverStream);
                executorService.submit(new AcceptPeerInitiatedStream(serverConnection, serverStream));
            }
        };
    }

    private class AcceptPeerInitiatedStream implements Runnable {
        private final QuicConnection serverConnection;
        private final tech.kwik.core.QuicStream serverStream;

        AcceptPeerInitiatedStream(QuicConnection serverConnection, tech.kwik.core.QuicStream serverStream) {
            this.serverConnection = serverConnection;
            this.serverStream = serverStream;
        }

        @Override
        public void run() {
            if (!clientConnection.isConnected()) {
                serverStream.resetStream(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value);
                serverConnection.close();
                return;
            }

            try {
                boolean bidirectional = serverStream.isBidirectional();
                tech.kwik.core.QuicStream clientStream = clientConnection.createStream(bidirectional);
                log.debug("createStream bidirectional={}, clientStream={}, serverStream={}", bidirectional, clientStream, serverStream);
                QuicStream server = new KwikStream(serverStream);
                QuicStream client = new KwikStream(clientStream);
                QuicStreamForward.startForward(server, client, bidirectional, executorService, new Http2SessionKey(session, serverStream.getStreamId(), true), http2Filter);
            } catch (Exception e) {
                log.debug("createStream", e);
                serverStream.resetStream(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value);
            }
        }
    }
}

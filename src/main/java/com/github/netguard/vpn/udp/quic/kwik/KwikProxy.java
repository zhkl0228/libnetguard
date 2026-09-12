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
import tech.kwik.core.server.ApplicationProtocolSettings;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

class KwikProxy implements ApplicationProtocolConnectionFactory {

    private static final Logger log = LoggerFactory.getLogger(KwikProxy.class);
    private final ExecutorService executorService;
    private final QuicClientConnection clientConnection;
    private final Http2Session session;
    private final Http2Filter http2Filter;

    /**
     * 允许客户端并发打开的流数，同时是 {@link ApplicationProtocolSettings} 给这两个值定的上限。
     * kwik 取二者的较小值（ServerConnectionConfigImpl#merge），所以这里和
     * {@link KwikHandshakeResult#startServer} 里的 ServerConnectionConfig 必须是同一个数。
     * <p>
     * 代理不该比客户端更早决定并发上限：客户端开几条我们就往上游转几条，所以取一个大到
     * 不会成为瓶颈的值，真正的限制由上游服务端的 transport parameters 施加在
     * {@link QuicClientConnection#createStream} 上。
     */
    static final int MAX_CONCURRENT_PEER_INITIATED_STREAMS = Short.MAX_VALUE;

    @Override
    public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
        return MAX_CONCURRENT_PEER_INITIATED_STREAMS;
    }

    @Override
    public int maxConcurrentPeerInitiatedBidirectionalStreams() {
        return MAX_CONCURRENT_PEER_INITIATED_STREAMS;
    }

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
            /**
             * 上游建流串成一条链，保证上游的 stream id 和客户端的一一对应。
             * <p>
             * kwik 按开流顺序、用单线程回调 acceptPeerInitiatedStream（QuicConnectionImpl 的
             * callbackThread 是 1 线程的 ThreadPoolExecutor），但每条流各自 submit 之后，谁先跑到
             * createStream 谁先拿到上游的 stream id，实测客户端的 6/10 会映射成上游的 10/6。
             * HTTP/3 单向流的类型写在负载首字节里，错位本身能跑通，但创建顺序不定意味着控制流的
             * SETTINGS 可能晚于第一个请求到达上游，而 RFC 9114 6.2.1 要求控制流在连接一开始就建立。
             * <p>
             * 链而不是直接在回调线程里建流：createStream 在上游没给流额度时会一直阻塞
             * （StreamManager 的默认超时是 10000 天），占住 kwik 的回调线程会连带堵死这条连接的
             * 断开通知。
             */
            private CompletableFuture<Void> streamChain = CompletableFuture.completedFuture(null);

            @Override
            public void acceptPeerInitiatedStream(tech.kwik.core.QuicStream serverStream) {
                log.debug("acceptPeerInitiatedStream serverStream={}", serverStream);
                streamChain = streamChain.thenRunAsync(new AcceptPeerInitiatedStream(serverConnection, serverStream), executorService);
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

        /**
         * 不抛异常：它是 streamChain 上的一环，抛出去会让这条连接后面所有的流都被跳过。
         */
        @Override
        public void run() {
            try {
                if (!clientConnection.isConnected()) {
                    // 上游已经断了，这条流没有去处。之前这里是静默的，症状就是"收到了流但什么都没发生"。
                    log.warn("acceptPeerInitiatedStream upstream disconnected: serverStream={}, serverConnection={}", serverStream, serverConnection);
                    serverStream.resetStream(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value);
                    serverConnection.close();
                    return;
                }

                boolean bidirectional = serverStream.isBidirectional();
                tech.kwik.core.QuicStream clientStream = clientConnection.createStream(bidirectional);
                log.debug("createStream bidirectional={}, clientStream={}, serverStream={}", bidirectional, clientStream, serverStream);
                QuicStream server = new KwikStream(serverStream);
                QuicStream client = new KwikStream(clientStream);
                QuicStreamForward.startForward(server, client, bidirectional, executorService, new Http2SessionKey(session, serverStream.getStreamId(), true), http2Filter);
            } catch (Exception e) {
                log.warn("createStream serverStream={}", serverStream, e);
                serverStream.resetStream(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value);
            }
        }
    }
}

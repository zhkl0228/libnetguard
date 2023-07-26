package com.github.netguard.vpn.ssl;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.IPacketCapture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

public class StreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(StreamForward.class);

    protected final InputStream inputStream;
    protected final OutputStream outputStream;
    /**
     * 是否做为服务端
     */
    protected final boolean server;
    protected final InetSocketAddress clientSocketAddress;
    protected final InetSocketAddress serverSocketAddress;
    private final CountDownLatch countDownLatch;
    private final Socket socket;
    protected final IPacketCapture packetCapture;
    protected final String hostName;
    private final boolean isSSL;

    protected StreamForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket,
                            IPacketCapture packetCapture, String hostName, boolean isSSL) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.server = server;
        this.clientSocketAddress = clientSocketAddress;
        this.serverSocketAddress = serverSocketAddress;
        this.countDownLatch = countDownLatch;
        this.socket = socket;
        this.packetCapture = packetCapture;
        this.hostName = hostName;
        this.isSSL = isSSL;
    }

    final void startThread() {
        Thread thread = new Thread(this, getClass().getSimpleName() + " for " + clientSocketAddress + "_" + serverSocketAddress);
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        doForward();
    }

    private Throwable socketException;

    protected boolean forward(byte[] buf) throws IOException {
        int read;
        try {
            while ((read = inputStream.read(buf)) != -1) {
                if (packetCapture != null) {
                    if (server) {
                        if (isSSL) {
                            packetCapture.onSSLProxyTx(clientSocketAddress, serverSocketAddress, Arrays.copyOf(buf, read));
                        } else {
                            packetCapture.onSocketTx(clientSocketAddress, serverSocketAddress, Arrays.copyOf(buf, read));
                        }
                    } else {
                        if (isSSL) {
                            packetCapture.onSSLProxyRx(clientSocketAddress, serverSocketAddress, Arrays.copyOf(buf, read));
                        } else {
                            packetCapture.onSocketRx(clientSocketAddress, serverSocketAddress, Arrays.copyOf(buf, read));
                        }
                    }
                }
                outputStream.write(buf, 0, read);
                outputStream.flush();
            }
            return true;
        } catch (SocketTimeoutException ignored) {
        }
        return false;
    }

    private void doForward() {
        try {
            byte[] buf = new byte[socket.getReceiveBufferSize()];
            while (socketException == null) {
                if (forward(buf)) {
                    break;
                }
            }
        } catch (SSLHandshakeException e) {
            if (log.isDebugEnabled()) {
                log.warn(String.format("handshake with %s => %s failed: {}", hostName, serverSocketAddress), e);
            } else {
                log.info(String.format("handshake with %s => %s failed: {}", hostName, serverSocketAddress), e.getMessage());
            }
            socketException = e;
        } catch (IOException e) {
            log.trace("stream forward exception: socket={}", socket, e);
            socketException = e;
        } catch (RuntimeException e) {
            log.warn("stream forward exception: socket={}", socket, e);
        } catch (Exception e) {
            log.debug("stream forward exception: socket={}", socket, e);
        } finally {
            IoUtil.close(inputStream);
            IoUtil.close(outputStream);
            countDownLatch.countDown();
        }
    }
}

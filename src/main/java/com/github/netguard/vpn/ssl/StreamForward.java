package com.github.netguard.vpn.ssl;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.IPacketCapture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
    protected final String clientIp, serverIp;
    protected final int clientPort, serverPort;
    private final CountDownLatch countDownLatch;
    private final Socket socket;
    protected final IPacketCapture packetCapture;
    protected final String hostName;
    private final boolean isSSL;

    protected StreamForward(InputStream inputStream, OutputStream outputStream, boolean server, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket,
                            IPacketCapture packetCapture, String hostName, boolean isSSL) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.server = server;
        this.clientIp = clientIp;
        this.serverIp = serverIp;
        this.clientPort = clientPort;
        this.serverPort = serverPort;
        this.countDownLatch = countDownLatch;
        this.socket = socket;
        this.packetCapture = packetCapture;
        this.hostName = hostName;
        this.isSSL = isSSL;
    }

    final void startThread() {
        Thread thread = new Thread(this, getClass().getSimpleName() + " for " + clientIp + ":" + clientPort + "_" + serverIp + ":" + serverPort);
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
                            packetCapture.onSSLProxyTx(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                        } else {
                            packetCapture.onSocketTx(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                        }
                    } else {
                        if (isSSL) {
                            packetCapture.onSSLProxyRx(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                        } else {
                            packetCapture.onSocketRx(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
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
                log.warn(String.format("handshake with %s => %s/%d failed: {}", hostName, serverIp, serverPort), e);
            } else {
                log.info(String.format("handshake with %s => %s/%d failed: {}", hostName, serverIp, serverPort), e.getMessage());
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

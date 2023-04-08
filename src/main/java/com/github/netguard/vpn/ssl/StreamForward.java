package com.github.netguard.vpn.ssl;

import com.github.netguard.vpn.IPacketCapture;
import org.apache.commons.io.IOUtils;
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

class StreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(StreamForward.class);

    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final boolean send;
    private final String clientIp, serverIp;
    private final int clientPort, serverPort;
    private final CountDownLatch countDownLatch;
    private final Socket socket;
    private final IPacketCapture packetCapture;
    private final String hostName;

    StreamForward(InputStream inputStream, OutputStream outputStream, boolean send, String clientIp, String serverIp, int clientPort, int serverPort, CountDownLatch countDownLatch, Socket socket,
                  IPacketCapture packetCapture, String hostName) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.send = send;
        this.clientIp = clientIp;
        this.serverIp = serverIp;
        this.clientPort = clientPort;
        this.serverPort = serverPort;
        this.countDownLatch = countDownLatch;
        this.socket = socket;
        this.packetCapture = packetCapture;
        this.hostName = hostName;

        Thread thread = new Thread(this, getClass().getSimpleName() + " for " + socket);
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        doForward();
    }

    private Throwable socketException;

    private void doForward() {
        try {
            byte[] buf = new byte[socket.getReceiveBufferSize()];
            int read;
            while (socketException == null) {
                try {
                    while ((read = inputStream.read(buf)) != -1) {
                        outputStream.write(buf, 0, read);
                        outputStream.flush();

                        if (packetCapture != null) {
                            if (send) {
                                packetCapture.onSSLProxyTX(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                            } else {
                                packetCapture.onSSLProxyRX(clientIp, serverIp, clientPort, serverPort, Arrays.copyOf(buf, read));
                            }
                        }
                    }
                    break;
                } catch (SocketTimeoutException ignored) {
                }
            }
        } catch (SSLHandshakeException e) {
            log.info(String.format("handshake with %s => %s/%d failed: {}", hostName, serverIp, serverPort), e.getMessage());
            socketException = e;
        } catch (IOException e) {
            log.trace("stream forward exception: socket={}", socket, e);
            socketException = e;
        } catch (Exception e) {
            log.debug("stream forward exception: socket={}", socket, e);
            socketException = e;
        } finally {
            IOUtils.closeQuietly(inputStream, outputStream);
            countDownLatch.countDown();
        }
    }
}

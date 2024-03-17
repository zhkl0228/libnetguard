package com.github.netguard.vpn.ssl;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Package;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
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
    private final InspectorVpn vpn;
    protected final IPacketCapture packetCapture;
    protected final String hostName;
    private final boolean isSSL;
    private final Packet packet;

    protected StreamForward(InputStream inputStream, OutputStream outputStream, boolean server, InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress, CountDownLatch countDownLatch, Socket socket,
                            InspectorVpn vpn, String hostName, boolean isSSL, Packet packet) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.server = server;
        this.clientSocketAddress = clientSocketAddress;
        this.serverSocketAddress = serverSocketAddress;
        this.countDownLatch = countDownLatch;
        this.socket = socket;
        this.vpn = vpn;
        this.packetCapture = vpn == null ? null : vpn.getPacketCapture();
        this.hostName = hostName;
        this.isSSL = isSSL;
        this.packet = packet;
    }

    final void startThread() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Thread thread = new Thread(this, getClass().getSimpleName() + " for " + clientSocketAddress + "_" + serverSocketAddress + "_" + dateFormat.format(new Date()));
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
            Package[] applications = new Package[0];
            if (vpn != null && packet != null) {
                applications = vpn.queryApplications(packet.hashCode());
            }
            if (log.isDebugEnabled()) {
                log.warn("[{}]handshake with {} => {} failed: {}", server ? "AsServer" : "AsClient", hostName, serverSocketAddress, applications, e);
            } else {
                log.info("[{}]handshake with {} => {} failed: {}, applications={}", server ? "AsServer" : "AsClient", hostName, serverSocketAddress, e.getMessage(), applications);
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

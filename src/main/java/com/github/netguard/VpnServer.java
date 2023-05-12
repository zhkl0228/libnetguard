package com.github.netguard;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.VpnListener;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Download root cert: <a href="http://88.88.88.88:88">LINK</a>
 */
public class VpnServer {

    private static final Logger log = LoggerFactory.getLogger(VpnServer.class);

    private static final int UDP_PORT = 20230;

    private final ServerSocket serverSocket;

    public VpnServer() throws IOException {
        this(UDP_PORT);
    }

    public VpnServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
    }

    private VpnListener vpnListener;

    public void setVpnListener(VpnListener vpnListener) {
        this.vpnListener = vpnListener;
    }

    private final List<ProxyVpn> clients = new ArrayList<>();

    private boolean useNetGuardCore = true;

    @SuppressWarnings("unused")
    public void disableNetGuard() {
        useNetGuardCore = false;
    }

    private boolean broadcast;

    public void enableBroadcast(int broadcastSeconds) throws SocketException {
        broadcast = true;
        serverSocket.setSoTimeout(broadcastSeconds * 1000);
    }

    public void start() {
        if (thread != null) {
            throw new IllegalStateException("Already started.");
        }
        if (broadcast) {
            sendBroadcast();
        }
        thread = new Thread(() -> {
            while (!shutdown) {
                try {
                    Socket socket = serverSocket.accept();
                    ProxyVpn vpn = null;
                    if (useNetGuardCore) {
                        try {
                            vpn = new ServiceSinkhole(socket, clients);
                        } catch(UnsatisfiedLinkError e) {
                            log.debug("init ServiceSinkhole", e);
                            useNetGuardCore = false;
                        }
                    }
                    if (vpn == null) {
                        vpn = new ProxyVpnRunnable(socket, clients);
                    }
                    if (vpnListener != null) {
                        vpnListener.onConnectClient(vpn);
                    }
                    Thread vpnThread = new Thread(vpn, "socket: " + socket);
                    vpnThread.setPriority(Thread.MAX_PRIORITY);
                    vpnThread.start();
                    clients.add(vpn);
                } catch (SocketTimeoutException e) {
                    if (broadcast) {
                        sendBroadcast();
                    }
                } catch (SocketException ignored) {
                } catch (IOException e) {
                    log.warn("accept", e);
                }
            }
        }, getClass().getSimpleName());
        thread.start();
    }

    private boolean shutdown;
    private Thread thread;

    public void shutdown() {
        if (shutdown) {
            throw new IllegalStateException("Already shutdown.");
        }
        shutdown = true;
        IoUtil.close(serverSocket);
        for (ProxyVpn vpn : clients.toArray(new ProxyVpn[0])) {
            vpn.stop();
        }
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException ignored) {
            }
        }
    }

    private void sendBroadcast() {
        try (DatagramSocket datagramSocket = new DatagramSocket()) {
            byte[] magic = "vpn".getBytes();
            ByteBuffer buffer = ByteBuffer.allocate(7);
            buffer.putShort((short) magic.length);
            buffer.put(magic);
            buffer.putShort((short) serverSocket.getLocalPort());

            byte[] data = buffer.array();
            if (log.isTraceEnabled()) {
                log.trace(Inspector.inspectString(data, "sendBroadcast"));
            }
            DatagramPacket packet = new DatagramPacket(data, data.length);
            packet.setPort(UDP_PORT);

            InetAddress broadcastAddr = InetAddress.getByName("255.255.255.255");
            packet.setAddress(broadcastAddr);
            datagramSocket.send(packet);
        } catch (IOException e) {
            log.trace("sendBroadcast", e);
        } catch (Exception e) {
            log.warn("sendBroadcast", e);
        }
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

}

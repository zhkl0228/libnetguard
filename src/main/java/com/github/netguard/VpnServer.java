package com.github.netguard;

import cn.banny.auxiliary.Inspector;
import cn.banny.utils.IOUtils;
import com.github.netguard.vpn.VpnListener;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

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

    @SuppressWarnings("unused")
    public void enableBroadcast(int broadcastSeconds) throws SocketException {
        broadcast = true;
        serverSocket.setSoTimeout(broadcastSeconds * 1000);
    }

    public void start() {
        if (thread != null) {
            throw new IllegalStateException("Already started.");
        }
        thread = new Thread(new Runnable() {
            @Override
            public void run() {
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
        IOUtils.close(serverSocket);
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

    private final byte[] buffer = new byte[128];

    private void sendBroadcast() {
        DatagramSocket datagramSocket = null;
        ByteArrayOutputStream baos = null;
        DataOutputStream dos = null;
        try {
            baos = new ByteArrayOutputStream();
            dos = new DataOutputStream(baos);
            datagramSocket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            dos.writeUTF("vpn");
            dos.writeShort(serverSocket.getLocalPort());

            byte[] data = baos.toByteArray();
            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(data, "sendBroadcast"));
            }
            packet.setData(data);
            packet.setLength(data.length);
            packet.setPort(UDP_PORT);

            InetAddress broadcastAddr = InetAddress.getByName("255.255.255.255");
            packet.setAddress(broadcastAddr);
            datagramSocket.send(packet);
        } catch (IOException ignored) {
        } catch (Exception e) {
            log.warn("sendBroadcast", e);
        } finally {
            IOUtils.close(dos);
            IOUtils.close(baos);
            if (datagramSocket != null) {
                datagramSocket.close();
            }
        }
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

}

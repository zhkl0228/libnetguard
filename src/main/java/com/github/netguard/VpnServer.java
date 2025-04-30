package com.github.netguard;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.handler.replay.FileReplay;
import com.github.netguard.handler.replay.Replay;
import com.github.netguard.sslvpn.SSLVpn;
import com.github.netguard.transparent.TransparentSocketProxying;
import com.github.netguard.vpn.BaseVpnListener;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.udp.UDPRelay;
import eu.faircode.netguard.ServiceSinkhole;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * java9: --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED
 * Download root cert: <a href="http://88.88.88.88:88">LINK</a>
 */
public class VpnServer {

    private static final Logger log = LoggerFactory.getLogger(VpnServer.class);

    @SuppressWarnings("unused")
    public static VpnServer startSimpleServer(PacketDecoder packetCapture) throws IOException {
        Calendar calendar = Calendar.getInstance();
        int year = calendar.get(Calendar.YEAR);
        int port = year * 10;
        VpnServer vpnServer = createSimpleBuilder(port, packetCapture).startServer();
        System.out.println("vpn server listen on: " + vpnServer.getPort());
        return vpnServer;
    }

    public static VpnServerBuilder createSimpleBuilder(int port, PacketDecoder packetCapture) {
        VpnServerBuilder builder = VpnServerBuilder.create();
        builder.withPort(port);
        builder.enableBroadcast(10);
        builder.withVpnListener(new BaseVpnListener() {
            @Override
            protected IPacketCapture createPacketCapture() {
                return packetCapture;
            }
        });
        return builder;
    }

    private static final int UDP_PORT = 20230;
    private static final int PROXY_PORT = 20238;
    private static final int NO_CLIENT_BROADCAST_DELAY_MILLIS = 1000;

    private final ServerSocket serverSocket;
    private final RootCert rootCert = RootCert.load();

    VpnServer() throws IOException {
        this(UDP_PORT);
    }

    VpnServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
    }

    private VpnListener vpnListener;

    final void setVpnListener(VpnListener vpnListener) {
        this.vpnListener = vpnListener;
    }

    private final List<ProxyVpn> clients = Collections.synchronizedList(new ArrayList<>());

    private boolean useNetGuardCore = true;

    final void disableNetGuard() {
        useNetGuardCore = false;
    }

    private boolean broadcast;
    private int broadcastSeconds;

    final void enableBroadcast(int broadcastSeconds) {
        if (broadcastSeconds < 1) {
            throw new IllegalArgumentException("broadcastSeconds=" + broadcastSeconds);
        }
        this.broadcast = true;
        this.broadcastSeconds = broadcastSeconds;
    }

    /**
     * see osx_pf/enable.sh
     */
    final void enableTransparentProxying() {
        enableTransparentProxying(PROXY_PORT);
    }

    private int transparentProxyingPort;
    private Thread transparentProxyingThread;
    private ServerSocket transparentProxyingSocketServer;

    final void enableTransparentProxying(int port) {
        this.transparentProxyingPort = port;
    }

    private boolean enableUdpRelay;
    private UDPRelay udpRelay;

    final void enableUdpRelay() {
        this.enableUdpRelay = true;
    }

    private Replay replay;

    /**
     * use BaseVpnListener
     */
    final void setReplayLogFile(File logFile) {
        replay = new FileReplay(this, logFile);
    }

    final void start() {
        if (thread != null) {
            throw new IllegalStateException("Already started.");
        }
        if (vpnListener != null && replay != null) {
            vpnListener.initializeReplay(replay);
        }
        if (broadcast) {
            sendBroadcast();
        }
        try {
            if (enableUdpRelay) {
                udpRelay = new UDPRelay(getPort());
            }
        } catch(IOException e) {
            log.warn("start udp relay failed.", e);
        }
        if (transparentProxyingPort > 0) {
            try {
                transparentProxyingSocketServer = new ServerSocket(transparentProxyingPort);
                transparentProxyingThread = new Thread(() -> {
                    while (!shutdown) {
                        try {
                            Socket socket = transparentProxyingSocketServer.accept();
                            ProxyVpn vpn = new TransparentSocketProxying(clients, rootCert, socket);
                            if (vpnListener != null) {
                                vpnListener.onConnectClient(vpn);
                            }
                            Thread vpnThread = new Thread(vpn, "socket: " + socket + "_TP");
                            vpnThread.setPriority(Thread.MAX_PRIORITY);
                            vpnThread.start();
                        } catch (SocketException ignored) {
                        } catch (IOException e) {
                            log.warn("accept", e);
                        }
                    }
                }, getClass().getSimpleName() + "_TP");
                transparentProxyingThread.start();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        thread = new Thread(() -> {
            while (!shutdown) {
                try {
                    if (clients.isEmpty()) {
                        serverSocket.setSoTimeout(NO_CLIENT_BROADCAST_DELAY_MILLIS);
                    }
                    Socket socket = serverSocket.accept();
                    final InputStream inputStream;
                    final int magic;
                    try {
                        PushbackInputStream pushbackInputStream = new PushbackInputStream(socket.getInputStream());
                        inputStream = pushbackInputStream;
                        magic = new DataInputStream(pushbackInputStream).readUnsignedByte();
                        if (magic == 0x16) {
                            pushbackInputStream.unread(magic);
                        }
                        log.debug("Accept client magic: 0x{}", Integer.toHexString(magic));
                    } catch (IOException e) {
                        IOUtils.closeQuietly(socket);
                        continue;
                    }
                    ProxyVpn vpn = null;
                    if (magic == 0x16) { // SSL
                        vpn = new SSLVpn(clients, rootCert, socket, inputStream,
                                getPort());
                    } else if (useNetGuardCore) {
                        try {
                            vpn = new ServiceSinkhole(socket, clients, rootCert, magic);
                        } catch (UnsatisfiedLinkError e) {
                            log.debug("init ServiceSinkhole", e);
                            useNetGuardCore = false;
                        } catch (IOException e) {
                            IOUtils.closeQuietly(socket);
                            continue;
                        }
                    }
                    if (vpn == null) {
                        try {
                            vpn = new ProxyVpnRunnable(socket, clients, rootCert, magic);
                        } catch (IOException e) {
                            IOUtils.closeQuietly(socket);
                            continue;
                        }
                    }
                    if (vpnListener != null) {
                        vpnListener.onConnectClient(vpn);
                    }
                    Thread vpnThread = new Thread(vpn, "socket: " + socket + ": vpn=" + vpn.getClass() + ", clientOS=" + vpn.getClientOS());
                    vpnThread.setPriority(Thread.MAX_PRIORITY);
                    vpnThread.start();
                    clients.add(vpn);
                    serverSocket.setSoTimeout(broadcastSeconds * 1000);
                } catch (SocketTimeoutException e) {
                    if (broadcast) {
                        sendBroadcast();
                    }
                } catch (SocketException ignored) {
                } catch (Exception e) {
                    log.warn("accept", e);
                }
            }
        }, getClass().getSimpleName());
        thread.start();
    }

    public void waitShutdown() {
        try (Scanner scanner = new Scanner(System.in)) {
            String cmd;
            while ((cmd = scanner.nextLine()) != null) {
                if ("q".equals(cmd) || "exit".equals(cmd)) {
                    break;
                }
            }
            this.shutdown();
        }
    }

    private boolean shutdown;
    private Thread thread;

    public void shutdown() {
        if (shutdown) {
            throw new IllegalStateException("Already shutdown.");
        }
        shutdown = true;
        IoUtil.close(serverSocket);
        IoUtil.close(transparentProxyingSocketServer);
        IoUtil.close(udpRelay);
        for (ProxyVpn vpn : clients.toArray(new ProxyVpn[0])) {
            vpn.stop();
        }
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException ignored) {
            }
        }
        if (transparentProxyingThread != null) {
            try {
                transparentProxyingThread.join();
            } catch (InterruptedException ignored) {
            }
        }
    }

    private void sendBroadcast() {
        try (DatagramSocket datagramSocket = new DatagramSocket()) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            DataOutput dataOutput = new DataOutputStream(outputStream);
            dataOutput.writeUTF("vpn");
            dataOutput.writeShort(serverSocket.getLocalPort());

            byte[] data = outputStream.toByteArray();
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

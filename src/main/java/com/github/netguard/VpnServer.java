package com.github.netguard;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import com.github.netguard.transparent.TransparentProxying;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.ssl.RootCert;
import eu.faircode.netguard.ServiceSinkhole;
import name.neykov.secrets.AgentAttach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Download root cert: <a href="http://88.88.88.88:88">LINK</a>
 */
public class VpnServer {

    private static final Logger log = LoggerFactory.getLogger(VpnServer.class);

    private static final int UDP_PORT = 20230;
    private static final int PROXY_PORT = 20238;

    private final ServerSocket serverSocket;
    private final RootCert rootCert = RootCert.load();

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

    /**
     * see osx_pf/enable.sh
     */
    public void enableTransparentProxying() {
        enableTransparentProxying(PROXY_PORT);
    }

    private int transparentProxyingPort;
    private Thread transparentProxyingThread;
    private ServerSocket transparentProxyingServer;

    public void enableTransparentProxying(int port) {
        this.transparentProxyingPort = port;
    }

    public void start() {
        if (thread != null) {
            throw new IllegalStateException("Already started.");
        }
        if (broadcast) {
            sendBroadcast();
        }
        if (transparentProxyingPort > 0) {
            try {
                transparentProxyingServer = new ServerSocket(transparentProxyingPort);
                transparentProxyingThread = new Thread(() -> {
                    while (!shutdown) {
                        try {
                            Socket socket = transparentProxyingServer.accept();
                            ProxyVpn vpn = new TransparentProxying(clients, rootCert, socket);
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
                    Socket socket = serverSocket.accept();
                    ProxyVpn vpn = null;
                    if (useNetGuardCore) {
                        try {
                            vpn = new ServiceSinkhole(socket, clients, rootCert);
                        } catch(UnsatisfiedLinkError e) {
                            log.debug("init ServiceSinkhole", e);
                            useNetGuardCore = false;
                        }
                    }
                    if (vpn == null) {
                        vpn = new ProxyVpnRunnable(socket, clients, rootCert);
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
        IoUtil.close(transparentProxyingServer);
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
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeUTF("vpn");
            dataOutput.writeShort(serverSocket.getLocalPort());

            byte[] data = baos.toByteArray();
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

    static {
        File preMasterSecretsLogFile = new File("target/pre_master_secrets.log");
        String preMasterSecretsLogPath = preMasterSecretsLogFile.getAbsolutePath();
        FileUtil.del(preMasterSecretsLogFile);
        CodeSource codeSource = AgentAttach.class.getProtectionDomain().getCodeSource();
        if (codeSource != null) {
            try {
                URL jarUrl = codeSource.getLocation();
                File jarFile = new File(jarUrl.toURI());
                String name = ManagementFactory.getRuntimeMXBean().getName();
                String pid = name.split("@")[0];
                String jarPath = jarFile.getAbsolutePath();
                System.out.printf("VM option: -javaagent:%s=%s%n", jarPath, preMasterSecretsLogPath);
                System.out.printf("java -jar %s %s %s%n", jarPath.replace(FileUtil.getUserHomePath(), "~"),
                        pid,
                        preMasterSecretsLogPath.replace(FileUtil.getUserHomePath(), "~"));
            } catch (URISyntaxException e) {
                throw new IllegalStateException(e);
            }
        }
    }

}

package com.github.netguard;

import cn.banny.utils.IOUtils;
import com.github.netguard.vpn.VpnListener;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

public class VpnServer {

    private static final Logger log = LoggerFactory.getLogger(VpnServer.class);

    private final ServerSocket serverSocket;

    public VpnServer() throws IOException {
        this(20230);
    }

    public VpnServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
    }

    private VpnListener vpnListener;

    public void setVpnListener(VpnListener vpnListener) {
        this.vpnListener = vpnListener;
    }

    private final List<ProxyVpn> clients = new ArrayList<>();

    private boolean useNetguard = true;

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
                        if (useNetguard) {
                            try {
                                vpn = new ServiceSinkhole(socket, clients);
                            } catch(UnsatisfiedLinkError e) {
                                log.debug("init ServiceSinkhole", e);
                                useNetguard = false;
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
                    } catch (SocketException ignored) {
                    }catch (IOException e) {
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

    public int getPort() {
        return serverSocket.getLocalPort();
    }
}

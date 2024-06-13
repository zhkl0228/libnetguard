package com.github.netguard.vpn.udp;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.Inspector;
import eu.faircode.netguard.Allowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public class UDProxy {

    private static final Logger log = LoggerFactory.getLogger(UDProxy.class);

    private static final int MTU = 1500;

    public static synchronized Allowed redirect(SocketAddress client, SocketAddress server) {
        log.debug("redirect client={}, server={}", client, server);
        try {
            UDProxy proxy = new UDProxy(client, server);
            return proxy.redirect();
        } catch (SocketException e) {
            throw new IllegalStateException("redirect", e);
        }
    }

    private final SocketAddress client;
    private final SocketAddress server;
    private final DatagramSocket clientSocket;
    private final DatagramSocket serverSocket;

    private UDProxy(SocketAddress client, SocketAddress server) throws SocketException {
        this.client = client;
        this.server = server;
        this.serverSocket = new DatagramSocket(new InetSocketAddress(0));
        this.serverSocket.setSoTimeout(60000);
        this.clientSocket = new DatagramSocket(new InetSocketAddress(0));
        this.clientSocket.setSoTimeout(60000);
        log.debug("UDProxy client={}, server={}, clientSocket={}, serverSocket={}", client, server, clientSocket.getLocalPort(), serverSocket.getLocalPort());

        Thread serverThread = new Thread(new Server(), "UDProxy server " + client + " => " + server);
        serverThread.setDaemon(true);
        serverThread.start();
        Thread clientThread = new Thread(new Client(), "UDProxy client " + client + " => " + server);
        clientThread.setDaemon(true);
        clientThread.start();
    }

    private Allowed redirect() {
        return new Allowed("127.0.0.1", serverSocket.getLocalPort());
    }

    private boolean serverClosed;
    private SocketAddress vpnAddress;

    private class Server implements Runnable {
        @Override
        public void run() {
            try {
                byte[] buffer = new byte[MTU];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                while (true) {
                    try {
                        serverSocket.receive(packet);
                        int length = packet.getLength();
                        if (log.isDebugEnabled()) {
                            byte[] data = new byte[length];
                            System.arraycopy(buffer, 0, data, 0, length);
                            log.debug("{}", Inspector.inspectString(data, "ServerReceived: " + client + " => " + server));
                        }
                        if (vpnAddress == null) {
                            vpnAddress = packet.getSocketAddress();
                        }
                        packet.setSocketAddress(server);
                        clientSocket.send(packet);
                    } catch (SocketTimeoutException e) {
                        break;
                    } catch (Exception e) {
                        log.warn("server", e);
                        break;
                    }
                }
            } finally {
                serverClosed = true;
                log.debug("udp proxy server exit: client={}, server={}", client, server);
            }
        }
    }

    private class Client implements Runnable {
        @Override
        public void run() {
            try {
                byte[] buffer = new byte[MTU];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                while (true) {
                    try {
                        clientSocket.receive(packet);
                        int length = packet.getLength();
                        if (log.isDebugEnabled()) {
                            byte[] data = new byte[length];
                            System.arraycopy(buffer, 0, data, 0, length);
                            log.debug("{}", Inspector.inspectString(data, "ClientReceived: " + client + " => " + server));
                        }
                        if (vpnAddress == null) {
                            throw new IllegalStateException("vpnAddress is null");
                        }
                        packet.setSocketAddress(vpnAddress);
                        serverSocket.send(packet);
                    } catch (SocketTimeoutException e) {
                        if (serverClosed) {
                            break;
                        }
                    } catch (Exception e) {
                        log.warn("client", e);
                        break;
                    }
                }
            } finally {
                IoUtil.close(serverSocket);
                IoUtil.close(clientSocket);
                log.debug("udp proxy client exit: client={}, server={}", client, server);
            }
        }
    }

}

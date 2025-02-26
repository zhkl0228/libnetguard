package com.github.netguard;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.PortRedirector;
import com.github.netguard.vpn.tcp.RootCert;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import eu.faircode.netguard.ServiceSinkhole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.httptoolkit.android.vpn.ClientPacketWriter;
import tech.httptoolkit.android.vpn.SessionHandler;
import tech.httptoolkit.android.vpn.SessionManager;
import tech.httptoolkit.android.vpn.socket.SocketNIODataService;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

class ProxyVpnRunnable extends ProxyVpn implements PortRedirector {

    private static final Logger log = LoggerFactory.getLogger(ProxyVpnRunnable.class);

    private final Socket socket;

    // Packets from device apps downstream, heading upstream via this VPN
    private final DataInputStream vpnReadStream;

    private final ClientPacketWriter vpnPacketWriter;
    private final Thread vpnPacketWriterThread;

    private final SocketNIODataService nioService;
    private final Thread dataServiceThread;

    private final SessionHandler handler;

    private final ByteBuffer packet = ByteBuffer.allocate(65536);

    private final ExecutorService pingThreadPool;

    ProxyVpnRunnable(Socket socket, List<ProxyVpn> clients, RootCert rootCert) throws IOException {
        super(clients, rootCert);
        this.socket = socket;
        this.vpnReadStream = new DataInputStream(socket.getInputStream());
        this.clientOS = readOS(this, vpnReadStream);

        // Packets from upstream servers, received by this VPN
        OutputStream vpnWriteStream = socket.getOutputStream();
        this.vpnPacketWriter = new ClientPacketWriter(new DataOutputStream(vpnWriteStream), packetCapture);

        this.vpnPacketWriterThread = new Thread(vpnPacketWriter);
        this.nioService = new SocketNIODataService(vpnPacketWriter);
        this.dataServiceThread = new Thread(nioService, "Socket NIO thread: " + socket);

        // Pool of threads to synchronously proxy ICMP ping requests in the background. We need to
        // carefully limit these, or a ping flood can cause us big big problems.
        this.pingThreadPool = new ThreadPoolExecutor(
                1, 20, // 1 - 20 parallel pings max
                60L, TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                new ThreadPoolExecutor.DiscardPolicy() // Replace running pings if there's too many
        );
        SessionManager manager = new SessionManager(this);
        this.handler = new SessionHandler(manager, nioService, vpnPacketWriter, pingThreadPool, packetCapture);
    }

    private boolean running;

    @Override
    protected void doRunVpn() {
        if (running) {
            log.warn("Vpn runnable started, but it's already running");
            return;
        }
        log.debug("Vpn thread starting");

        dataServiceThread.start();
        vpnPacketWriterThread.start();

        running = true;
        while (running) {
            try {
                byte[] data = packet.array();

                int length = vpnReadStream.readUnsignedShort();
                vpnReadStream.readFully(data, 0, length);
                if (length > 0) {
                    try {
                        packet.limit(length);
                        for (int i = 0; i < length; i++) {
                            data[i] ^= ServiceSinkhole.VPN_MAGIC;
                        }
                        handler.handlePacket(packet);
                    } catch (Exception e) {
                        log.trace("handlePacket", e);
                    }

                    packet.clear();
                } else {
                    TimeUnit.MILLISECONDS.sleep(10);
                }
            } catch (InterruptedException e) {
                log.info("Sleep interrupted", e);
            } catch (IOException e) {
                log.debug("Read interrupted", e);
                if (running) {
                    stop();
                }
            }
        }

        IoUtil.close(socket);
        log.debug("Vpn thread shutting down");

        clients.remove(this);

        if (packetCapture != null) {
            packetCapture.notifyVpnFinish();
        }
    }

    @Override
    protected synchronized void stop() {
        if (running) {
            running = false;
            IoUtil.close(vpnReadStream);
            nioService.shutdown();
            dataServiceThread.interrupt();

            vpnPacketWriter.shutdown();
            vpnPacketWriterThread.interrupt();

            pingThreadPool.shutdownNow();
        } else {
            log.debug("Vpn runnable stopped, but it's not running");
        }
    }

    @Override
    public Allowed redirectTcp(String saddr, int sport, String daddr, int dport) {
        if (directAllowAll) {
            return null;
        }
        Packet packet = new Packet();
        packet.version = Packet.IP_V4;
        packet.protocol = Packet.TCP_PROTOCOL;
        packet.saddr = saddr;
        packet.sport = sport;
        packet.daddr = daddr;
        packet.dport = dport;
        Allowed allowed = redirectTcp(packet);
        if (allowed.raddr != null && allowed.rport > 0) {
            return allowed;
        } else {
            return null;
        }
    }

    @Override
    public Allowed redirectUdp(String saddr, int sport, String daddr, int dport) {
        if (directAllowAll) {
            return null;
        }
        Packet packet = new Packet();
        packet.version = Packet.IP_V4;
        packet.protocol = Packet.UDP_PROTOCOL;
        packet.saddr = saddr;
        packet.sport = sport;
        packet.daddr = daddr;
        packet.dport = dport;
        Allowed allowed = redirectUdp(packet);
        if (allowed.raddr != null && allowed.rport > 0) {
            return allowed;
        } else {
            return null;
        }
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }
}

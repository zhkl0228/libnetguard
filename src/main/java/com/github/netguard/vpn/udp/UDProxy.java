package com.github.netguard.vpn.udp;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Allowed;
import net.luminis.quic.core.Role;
import net.luminis.quic.core.Version;
import net.luminis.quic.core.VersionHolder;
import net.luminis.quic.crypto.Aead;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.receive.Receiver;
import net.luminis.tls.handshake.ClientHello;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Message;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.List;

public class UDProxy {

    private static final Logger log = LoggerFactory.getLogger(UDProxy.class);

    private static final int MTU = Receiver.MAX_DATAGRAM_SIZE;
    private static final int READ_TIMEOUT = 60000;

    public static Allowed redirect(InspectorVpn vpn, SocketAddress client, SocketAddress server) {
        log.debug("redirect client={}, server={}", client, server);
        try {
            UDProxy proxy = new UDProxy(vpn, client, server);
            return proxy.redirect();
        } catch (SocketException e) {
            throw new IllegalStateException("redirect", e);
        }
    }

    private final InspectorVpn vpn;
    private final SocketAddress client;
    private final SocketAddress server;
    private final DatagramSocket clientSocket;
    private final DatagramSocket serverSocket;

    private UDProxy(InspectorVpn vpn, SocketAddress client, SocketAddress server) throws SocketException {
        this.vpn = vpn;
        this.client = client;
        this.server = server;
        this.serverSocket = new DatagramSocket(new InetSocketAddress(0));
        this.serverSocket.setSoTimeout(READ_TIMEOUT);
        this.clientSocket = new DatagramSocket(new InetSocketAddress(0));
        this.clientSocket.setSoTimeout(READ_TIMEOUT);
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

    private Message dnsQuery;

    private class Server implements Runnable {
        @Override
        public void run() {
            IPacketCapture packetCapture = vpn.getPacketCapture();
            DNSFilter dnsFilter = packetCapture == null ? null : packetCapture.getDNSFilter();
            try {
                byte[] buffer = new byte[MTU];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                boolean first = true;
                while (true) {
                    try {
                        serverSocket.receive(packet);
                        if (vpnAddress == null) {
                            vpnAddress = packet.getSocketAddress();
                        }
                        int length = packet.getLength();
                        if (log.isDebugEnabled()) {
                            byte[] data = new byte[length];
                            System.arraycopy(buffer, 0, data, 0, length);
                            log.debug("{}", Inspector.inspectString(data, "ServerReceived: " + client + " => " + server + ", base64=" + Base64.encode(data)));
                        }
                        if (first) {
                            try {
                                ByteBuffer bb = ByteBuffer.wrap(buffer);
                                bb.limit(length);
                                bb.mark();
                                int flags = bb.get() & 0xff;
                                if ((flags & 0x80) == 0x80 && bb.remaining() > 5) {
                                    int version = bb.getInt();
                                    if (log.isDebugEnabled()) {
                                        log.debug("detect quic flags=0x{}, version=0x{}", Integer.toHexString(flags), Integer.toHexString(version));
                                    }
                                    if (version == Version.QUIC_version_1.getId() && bb.remaining() > 10) {
                                        Version quicVersion = Version.parse(version);
                                        int dcidLength = bb.get() & 0xff;
                                        byte[] dcid = new byte[dcidLength];
                                        bb.get(dcid);
                                        int type = (flags & 0x30) >> 4;
                                        if (InitialPacket.isInitial(type, quicVersion)) {
                                            InitialPacket initialPacket = new InitialPacket(quicVersion);
                                            ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(quicVersion), Role.Server, null, new NullLogger());
                                            connectionSecrets.computeInitialKeys(dcid);

                                            bb.reset();
                                            Aead aead = connectionSecrets.getPeerAead(initialPacket.getEncryptionLevel());
                                            net.luminis.quic.log.Logger logger;
                                            if (log.isDebugEnabled()) {
                                                logger = new SysOutLogger();
                                                logger.logDebug(true);
                                            } else {
                                                logger = new NullLogger();
                                            }
                                            initialPacket.parse(bb, aead, 0, logger, 0);
                                            log.debug("initialPacket={}", initialPacket);
                                            List<QuicFrame> frameList = initialPacket.getFrames();
                                            QuicFrame firstFrame;
                                            if (!frameList.isEmpty() && (firstFrame = frameList.get(0)) instanceof CryptoFrame) {
                                                CryptoFrame cryptoFrame = (CryptoFrame) firstFrame;
                                                ClientHello clientHello = new ClientHello(ByteBuffer.wrap(cryptoFrame.getStreamData()), null);
                                                if (log.isDebugEnabled()) {
                                                    log.debug("{}", Inspector.inspectString(cryptoFrame.getStreamData(), "initialPacket.cryptoFrame clientHello=" + clientHello));
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch(Exception e) {
                                log.warn("check quic", e);
                            }
                            try {
                                ByteBuffer bb = ByteBuffer.wrap(buffer);
                                bb.limit(length);
                                Message message = new Message(bb);
                                if (!message.getSection(0).isEmpty()) {
                                    dnsQuery = message;
                                }
                                if (dnsQuery != null && dnsFilter != null) {
                                    Message fake = dnsFilter.cancelDnsQuery(dnsQuery);
                                    if (fake != null) {
                                        log.trace("cancelDnsQuery: {}", fake);
                                        byte[] fakeResponse = fake.toWire();
                                        DatagramPacket fakePacket = new DatagramPacket(fakeResponse, fakeResponse.length);
                                        fakePacket.setSocketAddress(vpnAddress);
                                        serverSocket.send(fakePacket);
                                        continue;
                                    }
                                }
                            } catch (IOException | BufferUnderflowException e) {
                                log.trace("decode dns request", e);
                            } catch (Exception e) {
                                log.warn("decode dns request", e);
                            }
                        }
                        packet.setSocketAddress(server);
                        clientSocket.send(packet);
                    } catch (SocketTimeoutException e) {
                        break;
                    } catch (Exception e) {
                        log.warn("server", e);
                        break;
                    } finally {
                        first = false;
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
            IPacketCapture packetCapture = vpn.getPacketCapture();
            DNSFilter dnsFilter = packetCapture == null ? null : packetCapture.getDNSFilter();
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
                        if (dnsQuery != null) {
                            try {
                                ByteBuffer bb = ByteBuffer.wrap(buffer);
                                bb.limit(length);
                                Message dnsResponse = new Message(bb);
                                log.trace("client={}, server={}, dnsQuery={}\ndnsResponse={}", client, server, dnsQuery, dnsResponse);

                                if (dnsFilter != null) {
                                    Message fake = dnsFilter.filterDnsResponse(dnsQuery, dnsResponse);
                                    if (fake != null) {
                                        log.trace("filterDnsResponse: {}", fake);
                                        byte[] fakeResponse = fake.toWire();
                                        DatagramPacket fakePacket = new DatagramPacket(fakeResponse, fakeResponse.length);
                                        fakePacket.setSocketAddress(vpnAddress);
                                        serverSocket.send(fakePacket);
                                        continue;
                                    }
                                }
                            } catch (Exception e) {
                                log.warn("decode dns response, query={}", dnsQuery, e);
                            }
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

package com.github.netguard.vpn.udp;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.github.netguard.Inspector;
import com.github.netguard.proxy.socks5.Socks5DatagramPacketHandler;
import com.github.netguard.vpn.AcceptUdpResult;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.tcp.h2.Http2Session;
import com.github.netguard.vpn.udp.quic.ClientConnection;
import com.github.netguard.vpn.udp.quic.HandshakeResult;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
import com.github.netguard.vpn.udp.quic.QuicServer;
import eu.faircode.netguard.Allowed;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Message;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.LongHeaderPacket;
import tech.kwik.core.packet.VersionNegotiationPacket;
import tech.kwik.core.receive.Receiver;
import tech.kwik.core.stream.ReceiveBuffer;
import tech.kwik.core.stream.ReceiveBufferImpl;
import tech.kwik.core.stream.StreamElement;
import tech.kwik.core.tls.QuicTransportParametersExtension;

import java.io.IOException;
import java.net.*;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;

public class UDProxy {

    private static final Logger log = LoggerFactory.getLogger(UDProxy.class);

    private static final int READ_TIMEOUT = 60000;

    public static Allowed redirect(InspectorVpn vpn, Packet packet) {
        if ("255.255.255.255".equals(packet.daddr)) {
            return new Allowed();
        }
        log.trace("redirect packet={}", packet);
        try {
            UDProxy proxy = new UDProxy(vpn, packet);
            return proxy.redirect();
        } catch (SocketException e) {
            throw new IllegalStateException("redirect", e);
        }
    }

    private final InspectorVpn vpn;
    private final InetSocketAddress clientAddress;
    private final InetSocketAddress serverAddress;
    private final DatagramSocket remoteSocket;
    private final DatagramSocket localSocket;
    private final Http2Filter http2Filter;
    private final DNSFilter dnsFilter;

    private UDProxy(InspectorVpn vpn, Packet packet) throws SocketException {
        this.vpn = vpn;
        this.clientAddress = packet.createClientAddress();
        this.serverAddress = packet.createServerAddress();
        this.localSocket = new DatagramSocket(0);
        this.localSocket.setSoTimeout(READ_TIMEOUT);
        this.remoteSocket = new DatagramSocket(0);
        this.remoteSocket.setSoTimeout(3000);
        log.trace("UDProxy client={}, server={}, remoteSocket={}, localSocket={}", clientAddress, serverAddress, remoteSocket.getLocalPort(), localSocket.getLocalPort());
        IPacketCapture packetCapture = vpn.getPacketCapture();
        this.http2Filter = packetCapture == null ? null : packetCapture.getH2Filter();
        this.dnsFilter = packetCapture == null ? null : packetCapture.getDNSFilter();

        ExecutorService executorService = vpn.getExecutorService();
        Client client = new Client();
        executorService.submit(new Server(client, serverAddress, packet));
        executorService.submit(client);
    }

    private Allowed redirect() {
        return new Allowed("127.0.0.1", localSocket.getLocalPort());
    }

    private boolean serverClosed;

    private class Server implements Runnable, ProxyContext {
        private final Client client;
        private final Packet packet;
        Server(Client client, InetSocketAddress serverAddress, Packet packet) {
            this.client = client;
            this.forwardAddress = serverAddress;
            this.packet = packet;
        }
        private InetSocketAddress forwardAddress;
        private final List<QuicFrame> bufferFrames = new ArrayList<>(10);
        private boolean continueQuic;
        @Override
        public void run() {
            IPacketCapture packetCapture = vpn.getPacketCapture();
            try {
                final byte[] buffer = new byte[Receiver.MAX_DATAGRAM_SIZE];
                final DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                boolean firstPacket = true;
                List<byte[]> pendingList = new ArrayList<>(10);
                while (true) {
                    try {
                        packet.setLength(buffer.length);
                        localSocket.receive(packet);
                        final int length = packet.getLength();
                        if (log.isDebugEnabled()) {
                            byte[] data = Arrays.copyOf(buffer, length);
                            if (client.connection == null) {
                                log.trace("{}", Inspector.inspectString(data, "ServerReceived: " + clientAddress + " => " + serverAddress + ", base64=" + Base64.encode(data)));
                            } else {
                                log.debug("{}", Inspector.inspectString(data, "ServerReceived: " + clientAddress + " => " + serverAddress + ", base64=" + Base64.encode(data)));
                            }
                        }
                        if (firstPacket || continueQuic) {
                            if (firstPacket) {
                                client.forwardAddress = (InetSocketAddress) packet.getSocketAddress();
                            }
                            ClientHello clientHello = null;
                            if (client.dnsQuery == null || continueQuic) {
                                try {
                                    clientHello = detectQuicClientHello(buffer, length);
                                    if (clientHello == null && continueQuic) {
                                        if (!bufferFrames.isEmpty()) {
                                            pendingList.add(Arrays.copyOf(buffer, length));
                                        }
                                        continue;
                                    }
                                } catch (ReassembleException e) {
                                    continueQuic = true;
                                    bufferFrames.addAll(e.frameList);
                                    pendingList.add(Arrays.copyOf(buffer, length));
                                    continue;
                                }
                            }
                            if (firstPacket) {
                                client.dnsQuery = detectDnsQuery(buffer, length);
                                log.trace("dnsQuery={}", client.dnsQuery);
                            }
                            Message fake;
                            if (dnsFilter != null &&
                                    client.dnsQuery != null &&
                                    (fake = dnsFilter.cancelDnsQuery(client.dnsQuery)) != null) {
                                log.trace("cancelDnsQuery: {}", fake);
                                byte[] fakeResponse = fake.toWire();
                                DatagramPacket fakePacket = new DatagramPacket(fakeResponse, fakeResponse.length);
                                fakePacket.setSocketAddress(client.forwardAddress);
                                localSocket.send(fakePacket);
                                continue;
                            }
                            if (packetCapture != null) {
                                PacketRequest packetRequest = new PacketRequest(buffer, length, clientHello, client.dnsQuery, serverAddress, vpn, this.packet);
                                AcceptUdpResult acceptUdpResult = packetCapture.acceptUdp(packetRequest);
                                AcceptRule rule = acceptUdpResult == null ? null : acceptUdpResult.acceptRule;
                                InetSocketAddress udpProxy = acceptUdpResult == null ? null : acceptUdpResult.udpProxy;
                                if (rule == null) {
                                    rule = AcceptRule.Forward;
                                }
                                log.trace("acceptUdp rule={}, packetRequest={}", rule, packetRequest);
                                switch (rule) {
                                    case Discard:
                                        throw new SocketTimeoutException("discard");
                                    case Forward: {
                                        setUdpProxy(packetRequest, udpProxy, acceptUdpResult == null ? null : acceptUdpResult.proxyHandler);
                                        break;
                                    }
                                    case FILTER_H3:
                                    case QUIC_MITM: {
                                        if (packetRequest.hostName == null ||
                                                packetRequest.hostName.isEmpty() ||
                                                packetRequest.applicationLayerProtocols.isEmpty()) {
                                            setUdpProxy(packetRequest, udpProxy, acceptUdpResult.proxyHandler);
                                            break; // forward traffic
                                        }
                                        Http2Filter http2Filter = rule == AcceptRule.FILTER_H3 ? UDProxy.this.http2Filter : null;
                                        handleQuicProxy(packetRequest, http2Filter, clientHello, packetCapture.getQuicProxyProvider(), udpProxy);
                                    }
                                }
                            }
                        }
                        for (byte[] data : pendingList) {
                            DatagramPacket pendingPacket = new DatagramPacket(data, data.length);
                            pendingPacket.setSocketAddress(forwardAddress);
                            sendToServer(pendingPacket);
                            if (log.isDebugEnabled()) {
                                log.debug("pendingPacket={}, length={}, hash={}, forwardAddress={}", pendingPacket, data.length, DigestUtil.md5Hex(data), forwardAddress);
                            }
                        }
                        pendingList.clear();
                        packet.setSocketAddress(forwardAddress);
                        sendToServer(packet);
                    } catch (SocketTimeoutException e) {
                        log.trace("server", e);
                        break;
                    } catch (Exception e) {
                        log.warn("server", e);
                        break;
                    } finally {
                        firstPacket = false;
                    }
                }
            } finally {
                serverClosed = true;
                log.trace("udp proxy server exit: client={}, server={}", clientAddress, serverAddress);
            }
        }

        private void setUdpProxy(PacketRequest packetRequest, InetSocketAddress udpProxy, ProxyHandler proxyHandler) throws IOException {
            UDProxy.this.udpProxy = udpProxy;
            if (udpProxy != null) {
                byte[] connect = UDPRelay.createConnectUdpRelayRequest(new InetSocketAddress(packetRequest.serverIp, packetRequest.port), 60);
                forwardAddress = udpProxy;
                DatagramPacket packet = new DatagramPacket(connect, connect.length);
                packet.setSocketAddress(forwardAddress);
                remoteSocket.send(packet);
            }
            if (proxyHandler != null) {
                proxyHandler.initContext(this);
                UDProxy.this.proxyHandler = proxyHandler;
            }
        }

        @Override
        public InetSocketAddress getClientAddress() {
            return clientAddress;
        }

        @Override
        public InetSocketAddress getServerAddress() {
            return serverAddress;
        }

        @Override
        public DatagramSocket getLocalSocket() {
            return localSocket;
        }

        @Override
        public DatagramSocket getRemoteSocket() {
            return remoteSocket;
        }

        private void handleQuicProxy(PacketRequest packetRequest, Http2Filter http2Filter, ClientHello clientHello, QuicProxyProvider quicProxyProvider, InetSocketAddress udpProxy) throws SocketTimeoutException {
            try {
                Duration connectTimeout = Duration.ofSeconds(60);
                for (Extension extension : clientHello.getExtensions()) {
                    if (extension instanceof QuicTransportParametersExtension) {
                        QuicTransportParametersExtension quicTransportParametersExtension = (QuicTransportParametersExtension) extension;
                        long timeout = quicTransportParametersExtension.getTransportParameters().getMaxIdleTimeout();
                        if (timeout >= 1000) {
                            connectTimeout = Duration.ofMillis(timeout);
                        }
                        break;
                    }
                }
                client.connection = quicProxyProvider.newClientConnection(packetRequest, connectTimeout, udpProxy);
                log.debug("handleQuic applicationLayerProtocols={}", packetRequest.applicationLayerProtocols);
                Http2Session session = new Http2Session(clientAddress.getHostString(), serverAddress.getHostString(), clientAddress.getPort(), serverAddress.getPort(), packetRequest.hostName);
                HandshakeResult handshakeResult = client.connection.handshake(session);
                log.debug("handleQuic handshakeResult={}", handshakeResult);
                client.quicServer = handshakeResult.startServer(vpn, http2Filter);
                forwardAddress = client.quicServer.getForwardAddress();
            } catch (Exception e) {
                IoUtil.close(client.connection);
                if (e instanceof IOException) {
                    log.debug("handleQuic packetRequest={}", packetRequest, e);
                } else {
                    log.warn("handleQuic packetRequest={}", packetRequest, e);
                }
                throw new SocketTimeoutException(e.getMessage());
            }
        }

        private Message detectDnsQuery(byte[] buffer, int length) {
            try {
                ByteBuffer bb = ByteBuffer.wrap(buffer);
                bb.limit(length);
                Message message = new Message(bb);
                if (!message.getSection(0).isEmpty()) {
                    return message;
                }
            } catch (IOException | BufferUnderflowException e) {
                log.trace("detectDnsQuery", e);
            } catch (Exception e) {
                log.warn("detectDnsQuery", e);
            }
            return null;
        }
        private ClientHello detectQuicClientHello(byte[] buffer, int length) throws ReassembleException {
            try {
                ByteBuffer bb = ByteBuffer.wrap(buffer);
                bb.limit(length);
                bb.mark();
                if (bb.remaining() < 1200) {
                    return null;
                }
                int flags = bb.get() & 0xff;
                if ((flags & 0x40) != 0x40) {
                    return null;
                }
                int type = (flags & 0x30) >> 4;
                if (LongHeaderPacket.isLongHeaderPacket((byte) flags, null)) {
                    int version = bb.getInt();
                    if (log.isDebugEnabled()) {
                        log.debug("detectQuicClientHello flags=0x{}, type={}, version=0x{}", Integer.toHexString(flags), type, Integer.toHexString(version));
                    }
                    int dcidLength = bb.get() & 0xff;
                    if (version == Version.QUIC_version_1.getId()) {
                        Version quicVersion = Version.parse(version);
                        byte[] dcid = new byte[dcidLength];
                        bb.get(dcid);
                        if (InitialPacket.isInitialType(type, quicVersion)) {
                            InitialPacket initialPacket = new InitialPacket(quicVersion);
                            ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(quicVersion), Role.Server, null, new NullLogger());
                            connectionSecrets.computeInitialKeys(dcid);

                            bb.reset();
                            Aead aead = connectionSecrets.getPeerAead(initialPacket.getEncryptionLevel());
                            tech.kwik.core.log.Logger logger;
                            if (log.isDebugEnabled()) {
                                logger = new SysOutLogger();
                                logger.logDebug(true);
                            } else {
                                logger = new NullLogger();
                            }
                            initialPacket.parse(bb, aead, 0, logger, 0);
                            log.debug("detectQuicClientHello initialPacket={}", initialPacket);
                            ReceiveBuffer receiveBuffer = new ReceiveBufferImpl();
                            for (QuicFrame frame : bufferFrames) {
                                if (frame instanceof StreamElement) {
                                    receiveBuffer.add((StreamElement) frame);
                                }
                            }
                            for(QuicFrame frame : initialPacket.getFrames()) {
                                if (frame instanceof StreamElement) {
                                    receiveBuffer.add((StreamElement) frame);
                                }
                            }
                            ByteBuffer block = ByteBuffer.allocate((int) receiveBuffer.bytesAvailable());
                            receiveBuffer.read(block);
                            if (log.isDebugEnabled()) {
                                log.debug("detectQuicClientHello receiveBuffer bytesAvailable={}, readOffset={}, allDataReceived={}, allRead={}, block.capacity={}", receiveBuffer.bytesAvailable(), receiveBuffer.readOffset(),
                                        receiveBuffer.allDataReceived(), receiveBuffer.allRead(), block.capacity());
                                log.debug("{}", Inspector.inspectString(block.array(), "detectQuicClientHello receiveBuffer"));
                            }
                            byte[] streamData = block.array();
                            if (streamData.length < 1 || streamData[0] != TlsConstants.HandshakeType.client_hello.value) {
                                log.warn("{}", Inspector.inspectString(streamData, "detectQuicClientHello frameList=" + initialPacket.getFrames()));
                            } else {
                                try {
                                    ClientHello clientHello = new ClientHello(ByteBuffer.wrap(streamData), null);
                                    if (log.isDebugEnabled()) {
                                        log.debug("{}", Inspector.inspectString(streamData, "detectQuicClientHello initialPacket.cryptoFrame"));
                                    }
                                    continueQuic = false;
                                    return clientHello;
                                } catch (DecodeErrorException e) {
                                    log.trace("detectQuicClientHello", e);
                                    throw new ReassembleException(initialPacket.getFrames());
                                }
                            }
                        } else {
                            log.warn("detectQuicClientHello type={}", type);
                        }
                    } else  {
                        if (dcidLength > 20) {
                            if (initialWithUnsupportedVersion(type, version, length)) {
                                log.debug("initialWithUnspportedVersion dcidLength={}", dcidLength);
                                // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                                // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                                sendVersionNegotiationPacket(client.forwardAddress, bb, dcidLength);
                                continueQuic = true;
                                return null;
                            }
                        }
                        if (bb.remaining() >= dcidLength + 1) {  // after dcid at least one byte scid length
                            byte[] dcid = new byte[dcidLength];
                            bb.get(dcid);
                            int scidLength = bb.get() & 0xff;
                            if (bb.remaining() >= scidLength) {
                                byte[] scid = new byte[scidLength];
                                bb.get(scid);
                                bb.rewind();

                                if (initialWithUnsupportedVersion(type, version, length)) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("initialWithUnspportedVersion dcid={}, scid={}", HexUtil.encodeHexStr(dcid), HexUtil.encodeHexStr(scid));
                                    }
                                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                                    // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                                    sendVersionNegotiationPacket(client.forwardAddress, bb, dcidLength);
                                    continueQuic = true;
                                    return null;
                                }
                            }
                        }
                        if (version == Version.QUIC_version_2.getId() ||
                                version == Version.IETF_draft_27.getId() ||
                                version == Version.IETF_draft_29.getId()) {
                            log.debug("detectQuicClientHello version=0x{}, length={}", Integer.toHexString(version), length);
                        } else {
                            log.warn("detectQuicClientHello version=0x{}, length={}, buffer={}", Integer.toHexString(version), length, HexUtil.encodeHexStr(Arrays.copyOf(buffer, length)));
                        }
                    }
                } else {
                    log.debug("detectQuicClientHello flags=0x{}, type={}, length={}", Integer.toHexString(flags), type, length);
                }
            } catch(ReassembleException e) {
                throw e;
            } catch(Exception e) {
                log.warn("detectQuicClientHello", e);
            }
            return null;
        }

        private void sendVersionNegotiationPacket(InetSocketAddress clientAddress, ByteBuffer data, int dcidLength) {
            data.rewind();
            if (data.remaining() >= 1 + 4 + 1 + dcidLength + 1) {
                byte[] dcid = new byte[dcidLength];
                data.position(1 + 4 + 1);
                data.get(dcid);
                int scidLength = data.get() & 0xff;
                byte[] scid = new byte[scidLength];
                if (scidLength > 0) {
                    data.get(scid);
                }
                // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.1
                // "The server MUST include the value from the Source Connection ID field of the packet it receives in the
                //  Destination Connection ID field. The value for Source Connection ID MUST be copied from the Destination
                //  Connection ID of the received packet, ..."
                VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(Version.QUIC_version_1, dcid, scid);
                byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(null);
                if (log.isDebugEnabled()) {
                    log.debug("sendVersionNegotiationPacket hash={}", DigestUtil.md5Hex(packetBytes));
                }
                DatagramPacket datagram = new DatagramPacket(packetBytes, packetBytes.length, clientAddress.getAddress(), clientAddress.getPort());
                try {
                    localSocket.send(datagram);
                } catch (IOException e) {
                    log.error("Sending version negotiation packet failed", e);
                }
            }
        }

        private boolean initialWithUnsupportedVersion(int type, int version, int length) {
            if (InitialPacket.isInitialType(type, Version.parse(version))) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-14.1
                // "A server MUST discard an Initial packet that is carried in a UDP
                //   datagram with a payload that is smaller than the smallest allowed
                //   maximum datagram size of 1200 bytes. "
                return length >= 1200;
            }
            return false;
        }
    }

    private void sendToServer(DatagramPacket packet) throws IOException {
        if (proxyHandler == null) {
            remoteSocket.send(packet);
        } else {
            byte[] buf = packet.getData();
            int newLength = proxyHandler.handleUdpClient((InetSocketAddress) packet.getSocketAddress(), buf, packet.getLength());
            sendProxyUdp(remoteSocket, packet, newLength);
        }
    }

    private void sendToClient(DatagramSocket socket, DatagramPacket packet) throws IOException {
        if (proxyHandler == null) {
            socket.send(packet);
        } else {
            byte[] buf = packet.getData();
            int newLength = proxyHandler.handleUdpServer((InetSocketAddress) packet.getSocketAddress(), buf, packet.getLength());
            sendProxyUdp(socket, packet, newLength);
        }
    }

    private void sendProxyUdp(DatagramSocket socket, DatagramPacket packet, int newLength) throws IOException {
        if (newLength > 0) {
            packet.setLength(newLength);
            socket.send(packet);
        }
    }

    private ProxyHandler proxyHandler;
    private InetSocketAddress udpProxy;

    private final Socks5DatagramPacketHandler socks5DatagramPacketHandler = new Socks5DatagramPacketHandler();

    private class Client implements Runnable {
        private InetSocketAddress forwardAddress;
        private Message dnsQuery;
        private ClientConnection connection;
        private QuicServer quicServer;
        private final Map<SocketAddress, DatagramSocket> sockets = new HashMap<>();
        private DatagramSocket selectSocket(SocketAddress address) throws IOException {
            if(serverAddress.equals(address)) {
                return localSocket;
            }
            DatagramSocket socket = sockets.get(address);
            if (socket != null) {
                return socket;
            }
            socket = new DatagramSocket(0);
            socket.setSoTimeout(READ_TIMEOUT);
            sockets.put(address, socket);
            log.debug("Creating new socket for {}", address);
            return socket;
        }
        @Override
        public void run() {
            try {
                final byte[] buffer = new byte[Receiver.MAX_DATAGRAM_SIZE];
                final DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                while (true) {
                    try {
                        packet.setData(buffer);
                        remoteSocket.receive(packet);
                        if (udpProxy != null) {
                            socks5DatagramPacketHandler.decapsulate(packet);
                        }
                        DatagramSocket socket = selectSocket(packet.getSocketAddress());
                        log.debug("Received packet: {}, udpProxy={}, serverAddress={}, localSocket={}, socket={}", packet.getSocketAddress(), udpProxy, serverAddress, localSocket, socket);
                        final int length = packet.getLength();
                        if (log.isDebugEnabled()) {
                            byte[] data = new byte[length];
                            System.arraycopy(buffer, 0, data, 0, length);
                            if (quicServer == null) {
                                log.trace("{}", Inspector.inspectString(data, String.format("ClientReceived: %s => %s", clientAddress, serverAddress)));
                            } else {
                                log.debug("{}", Inspector.inspectString(data, String.format("ClientReceived: %s => %s FROM %s", clientAddress, serverAddress, packet.getSocketAddress())));
                            }
                        }
                        if (forwardAddress == null) {
                            throw new IllegalStateException("vpnAddress is null");
                        }
                        if (dnsQuery != null) {
                            try {
                                ByteBuffer bb = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
                                bb.limit(length);
                                Message dnsResponse = new Message(bb);
                                log.trace("client={}, server={}, dnsQuery={}\ndnsResponse={}", clientAddress, serverAddress, dnsQuery, dnsResponse);

                                if (dnsFilter != null) {
                                    Message fake = dnsFilter.filterDnsResponse(dnsQuery, dnsResponse);
                                    if (fake != null) {
                                        log.trace("filterDnsResponse: {}", fake);
                                        byte[] fakeResponse = fake.toWire();
                                        DatagramPacket fakePacket = new DatagramPacket(fakeResponse, fakeResponse.length);
                                        fakePacket.setSocketAddress(forwardAddress);
                                        localSocket.send(fakePacket);
                                        continue;
                                    }
                                }
                            } catch (Exception e) {
                                log.warn("decode dns response, query={}", dnsQuery, e);
                            }
                        }
                        packet.setSocketAddress(forwardAddress);
                        sendToClient(socket, packet);
                    } catch (SocketTimeoutException e) {
                        log.trace("client", e);
                        if (serverClosed) {
                            break;
                        }
                    } catch (Exception e) {
                        log.warn("client", e);
                        break;
                    }
                }
            } finally {
                for(DatagramSocket socket : sockets.values()) {
                    IoUtil.close(socket);
                }
                IoUtil.close(quicServer);
                IoUtil.close(connection);
                IoUtil.close(localSocket);
                IoUtil.close(remoteSocket);
                log.trace("udp proxy client exit: client={}, server={}", clientAddress, serverAddress);
            }
        }
    }

}

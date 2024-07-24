package com.github.netguard.vpn.udp;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.thread.ThreadUtil;
import com.github.netguard.Inspector;
import net.luminis.quic.receive.Receiver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UDPRelay implements Runnable, Closeable {

    private static final Logger log = LoggerFactory.getLogger(UDPRelay.class);

    private final ExecutorService executorService = Executors.newCachedThreadPool(
            ThreadUtil.newNamedThreadFactory("udp-relay", true)
    );
    private final DatagramSocket serverSocket;

    public UDPRelay(int port) throws SocketException {
        this.serverSocket = new DatagramSocket(port);
        this.executorService.submit(this);
    }

    private class Relay implements Runnable {
        private final DatagramSocket clientSocket;
        private final SocketAddress clientAddress;
        private final SocketAddress serverAddress;
        public Relay(SocketAddress clientAddress, SocketAddress serverAddress, int receiveTimeoutSeconds) throws SocketException {
            this.clientSocket = new DatagramSocket();
            this.clientSocket.setSoTimeout((receiveTimeoutSeconds > 60 || receiveTimeoutSeconds <= 0 ? 60 : receiveTimeoutSeconds) * 1000);
            this.clientAddress = clientAddress;
            this.serverAddress = serverAddress;
        }
        @Override
        public void run() {
            byte[] buffer = new byte[Receiver.MAX_DATAGRAM_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                while (true) {
                    try {
                        clientSocket.receive(packet);
                        packet.setSocketAddress(clientAddress);
                        serverSocket.send(packet);
                    } catch (IOException e) {
                        log.debug("relay {} => {}", clientAddress, serverAddress, e);
                        break;
                    }
                }
            } finally {
                IoUtil.close(clientSocket);
                relayMap.remove(clientAddress);
                log.debug("exit relay: {}", clientAddress);
            }
        }
        private void forward(DatagramPacket packet) throws IOException {
            packet.setSocketAddress(serverAddress);
            clientSocket.send(packet);
        }
        @Override
        public String toString() {
            return "Relay{" +
                    "clientAddress=" + clientAddress +
                    ", serverAddress=" + serverAddress +
                    '}';
        }
    }

    private final Map<SocketAddress, Relay> relayMap = new ConcurrentHashMap<>();
    private static final byte[] CONNECT_MAGIC = "UDPR".getBytes();

    public static DatagramSocket createRelayProxySocket(InetSocketAddress udpProxy, InetSocketAddress serverAddress, long receiveTimeoutSeconds) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        byte[] setProxy = UDPRelay.createConnectUdpRelayRequest(serverAddress, (int) receiveTimeoutSeconds);
        DatagramPacket packet = new DatagramPacket(setProxy, setProxy.length);
        packet.setSocketAddress(udpProxy);
        socket.send(packet);
        return socket;
    }

    public static byte[] createConnectUdpRelayRequest(InetSocketAddress serverAddress, int receiveTimeoutSeconds) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.write(CONNECT_MAGIC);
            byte[] address = serverAddress.getAddress().getAddress();
            dataOutput.writeByte(address.length);
            dataOutput.write(address);
            dataOutput.writeShort(serverAddress.getPort());
            dataOutput.writeByte(receiveTimeoutSeconds);
            byte[] newPacket = baos.toByteArray();
            if(newPacket.length > Receiver.MAX_DATAGRAM_SIZE) {
                throw new IllegalStateException("UDP relay packet exceeds maximum UDP packet size");
            } else {
                return newPacket;
            }
        } catch (IOException e) {
            throw new IllegalStateException("createConnectUdpRelayRequest", e);
        }
    }

    @Override
    public void run() {
        byte[] buffer = new byte[Receiver.MAX_DATAGRAM_SIZE];
        final DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        byte[] magic = new byte[4];
        byte[] ipv4 = new byte[4];
        byte[] ipv6 = new byte[6];
        log.debug("start udp relay serverSocket={}", serverSocket);
        while (true) {
            try {
                serverSocket.receive(packet);
                int length = packet.getLength();
                SocketAddress clientAddress = packet.getSocketAddress();
                Relay relay = relayMap.get(clientAddress);
                log.debug("receive packet={}, clientAddress={}, relay={}, relaySize={}", packet, clientAddress, relay, relayMap.size());
                if (log.isDebugEnabled()) {
                    log.debug("{}", Inspector.inspectString(Arrays.copyOf(buffer, length), "receive packet"));
                }
                if (relay != null) {
                    try {
                        relay.forward(packet);
                    } catch (Exception e) {
                        log.debug("relay forward", e);
                    }
                } else if(length > 4) {
                    try {
                        ByteBuffer bb = ByteBuffer.wrap(buffer);
                        bb.limit(length);
                        bb.get(magic);
                        if (!Arrays.equals(magic, CONNECT_MAGIC)) {
                            continue;
                        }
                        int type = bb.get() & 0xff;
                        InetAddress address;
                        if (type == 4) {
                            bb.get(ipv4);
                            address = InetAddress.getByAddress(ipv4);
                        } else if (type == 6) {
                            bb.get(ipv6);
                            address = InetAddress.getByAddress(ipv6);
                        } else {
                            continue;
                        }
                        int port = bb.getShort() & 0xffff;
                        int receiveTimeoutInSeconds = bb.get() & 0xff;
                        if (bb.hasRemaining()) {
                            log.warn("bb={}", bb);
                        }
                        InetSocketAddress serverAddress = new InetSocketAddress(address, port);
                        relay = new Relay(clientAddress, new InetSocketAddress(address, port), receiveTimeoutInSeconds);
                        relayMap.put(clientAddress, relay);
                        executorService.submit(relay);
                        log.debug("connect relay serverAddress={}, relayMap={}", serverAddress, relayMap);
                    } catch (Exception e) {
                        log.debug("handle connect udp relay", e);
                    }
                }
            } catch (IOException e) {
                log.debug("run udp replay", e);
                break;
            } catch (Exception e) {
                log.warn("run udp replay", e);
            }
        }
        log.debug("exit udp replay");
    }

    @Override
    public void close() throws IOException {
        executorService.shutdown();
        IoUtil.close(serverSocket);
    }

}

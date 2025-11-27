package com.github.netguard;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import com.github.netguard.handler.PacketDecoder;
import com.github.netguard.handler.replay.FileReplay;
import com.github.netguard.handler.replay.Replay;
import com.github.netguard.transparent.TransparentSocketProxying;
import com.github.netguard.vpn.BaseVpnListener;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.VpnListener;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.ExtensionServerName;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.udp.UDPRelay;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.time.Duration;
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

    /**
     * 生成小火箭 socks5 QRCode
     */
    @SuppressWarnings("unused")
    public String generateShadowRocketQRCode() {
        if (!enableProxy) {
            throw new IllegalStateException("Enable proxy when generating shadow rocket QR code");
        }
        try {
            String lanIp = Inspector.detectLanIP();
            int port = getPort();
            List<String> list = new ArrayList<>(3);
            list.add("method=strict");
            list.add(String.format("remarks=Dev_%s:%d", lanIp, port));
            list.add("udp=0");
            return String.format("socks://%s?%s",
                    Base64.encodeUrlSafe((lanIp + ":" + port).getBytes()),
                    String.join("&", list));
        } catch (SocketException e) {
            throw new IllegalStateException("generateShadowRocketQRCode", e);
        }
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

    boolean enableProxy;

    /**
     * use BaseVpnListener
     */
    final void setReplayLogFile(File logFile) {
        replay = new FileReplay(this, logFile);
    }

    private ProxyVpnFactory fallbackVpnFactory;

    @SuppressWarnings("unused")
    public void setFallbackVpnFactory(ProxyVpnFactory fallbackVpnFactory) {
        this.fallbackVpnFactory = fallbackVpnFactory;
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
                    final Socket socket = serverSocket.accept();
                    final ProxyVpnFactory proxyVpnFactory;
                    final PushbackInputStream inputStream;
                    try {
                        socket.setSoTimeout(500);
                        inputStream = new PushbackInputStream(socket.getInputStream(), 20480);
                        DataInputStream dataInput = new DataInputStream(inputStream);
                        int os = dataInput.readUnsignedByte();
                        if ((os == 0x4 && checkRead(dataInput, inputStream, new byte[] { 0x1 })) ||
                                (os == 0x5 && checkSocksV5Read(dataInput, inputStream))) { // socks proxy
                            if (enableProxy) {
                                proxyVpnFactory = new ProxyVpnFactory.SocksProxyFactory(os == 0x5 ? ClientOS.SocksV5 : ClientOS.SocksV4);
                            } else {
                                throw new IOException("Proxy not enabled.");
                            }
                        } else if ((os == 'G' && checkRead(dataInput, inputStream, "ET".getBytes())) ||
                                (os == 'P' && (checkRead(dataInput, inputStream, "UT".getBytes()) || checkRead(dataInput, inputStream, "ATCH".getBytes()) || checkRead(dataInput, inputStream, "OST".getBytes()))) ||
                                (os == 'D' && checkRead(dataInput, inputStream, "ELETE".getBytes())) ||
                                (os == 'H' && checkRead(dataInput, inputStream, "EAD".getBytes())) ||
                                (os == 'O' && checkRead(dataInput, inputStream, "PTIONS".getBytes())) ||
                                (os == 'T' && checkRead(dataInput, inputStream, "RACE".getBytes()))) { // http proxy: GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, PATCH
                            if (enableProxy) {
                                inputStream.unread(os);
                                proxyVpnFactory = new ProxyVpnFactory.HttpProxyFactory();
                            } else {
                                throw new IOException("Proxy not enabled.");
                            }
                        } else if (os == 'C' && checkRead(dataInput, inputStream, "ONNECT".getBytes())) { // https proxy: CONNECT
                            if (enableProxy) {
                                inputStream.unread(os);
                                proxyVpnFactory = new ProxyVpnFactory.HttpsProxyFactory();
                            } else {
                                throw new IOException("Proxy not enabled.");
                            }
                        } else if (fallbackVpnFactory != null) {
                            inputStream.unread(os);
                            proxyVpnFactory = fallbackVpnFactory;
                        } else if (os == 0x16) {
                            inputStream.unread(os);
                            ClientHelloRecord clientHelloRecord = ExtensionServerName.parseServerNames(dataInput, (InetSocketAddress) socket.getRemoteSocketAddress());
                            log.debug("Accept client clientHelloRecord={}", clientHelloRecord);
                            if (clientHelloRecord.isSSL()) {
                                inputStream.unread(clientHelloRecord.prologue);
                            } else {
                                throw new EOFException("NOT SSL: " + clientHelloRecord);
                            }
                            proxyVpnFactory = new ProxyVpnFactory.SSLVpnFactory(getPort(), clientHelloRecord);
                        } else if ((Character.isLowerCase(os) || Character.isDigit(os)) && isTrajan(os, dataInput, inputStream)) { // may Trojan
                            proxyVpnFactory = new ProxyVpnFactory.TrojanProxyFactory();
                        } else {
                            proxyVpnFactory = new ProxyVpnFactory.VpnFactory(os, useNetGuardCore);
                        }
                        socket.setSoTimeout((int) Duration.ofHours(1).toMillis());
                    } catch (IOException e) {
                        log.debug("accept detect protocol", e);
                        IoUtil.close(socket);
                        continue;
                    }
                    final ProxyVpn vpn;
                    try {
                        vpn = proxyVpnFactory.newVpn(socket, clients, rootCert, inputStream);
                    } catch (IOException e) {
                        log.debug("accept newVpn", e);
                        IoUtil.close(socket);
                        continue;
                    }
                    if (vpnListener != null) {
                        vpnListener.onConnectClient(vpn);
                    }
                    Thread vpnThread = new Thread(vpn, "socket: " + socket + ": vpn=" + vpn.getClass() + ", clientOS=" + vpn.getClientOS());
                    vpnThread.setPriority(Thread.MAX_PRIORITY);
                    vpnThread.setDaemon(true);
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

    private boolean isTrajan(int os, DataInputStream dataInput, PushbackInputStream inputStream) throws IOException {
        inputStream.unread(os);
        byte[] passwdWithCommand = new byte[56 + 3];
        dataInput.readFully(passwdWithCommand);
        try {
            for (int i = 0; i < 56; i++) {
                int ch = passwdWithCommand[i] & 0xff;
                if (!Character.isLowerCase(ch) && !Character.isDigit(ch)) {
                    return false;
                }
            }
            return passwdWithCommand[56] == 0xd && passwdWithCommand[57] == 0xa && passwdWithCommand[58] == 0x1;
        } finally {
            inputStream.unread(passwdWithCommand);
        }
    }

    private boolean checkSocksV5Read(DataInputStream dataInput, PushbackInputStream inputStream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(16);
        try {
            int n = dataInput.readUnsignedByte();
            baos.write(n);
            if (n != 1 && n != 2) {
                return false;
            }
            for(int i = 0; i < n; i++) {
                int m = dataInput.readUnsignedByte();
                baos.write(m);
                // X’00’ NO AUTHENTICATION REQUIRED
                // X’02’ USERNAME/PASSWORD
                if (m != 0 && m != 2) {
                    return false;
                }
            }
            return true;
        } finally {
            inputStream.unread(baos.toByteArray());
        }
    }

    private boolean checkRead(DataInputStream dataInput, PushbackInputStream inputStream, byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(16);
        try {
            for (byte d : data) {
                byte b = dataInput.readByte();
                baos.write(b);
                if (b != d) {
                    return false;
                }
            }
            return true;
        } finally {
            inputStream.unread(baos.toByteArray());
        }
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

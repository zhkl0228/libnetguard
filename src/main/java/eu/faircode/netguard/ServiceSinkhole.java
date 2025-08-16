package eu.faircode.netguard;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.RootCert;
import org.scijava.nativelib.NativeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketImpl;
import java.net.SocketTimeoutException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ServiceSinkhole extends ProxyVpn implements InspectorVpn {

    private static final Logger log = LoggerFactory.getLogger(ServiceSinkhole.class);

    public static final byte VPN_MAGIC = 0xe;

    static {
        try {
            NativeLoader.loadLibrary("netguard");
        } catch (IOException ignored) {
        }
    }

    private static Field fdField;

    private final Socket socket;
    private final long jni_context;

    private static FileDescriptor getFileDescriptor(Socket socket) {
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(socket);
            Field f_fd = SocketImpl.class.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    private static int getFileDescriptorFromSocket(Socket socket) {
        try {
            FileDescriptor descriptor = jni_getFileDescriptorFromSocket(socket);
            return jni_getFd(descriptor);
        } catch (UnsatisfiedLinkError e) {
            log.trace("getFileDescriptorFromSocket", e);
        }
        try {
            FileDescriptor descriptor = getFileDescriptor(socket);
            if (fdField == null) {
                fdField = FileDescriptor.class.getDeclaredField("fd");
                fdField.setAccessible(true);
            }
            return (Integer) fdField.get(descriptor);
        } catch (Exception e) {
            throw new IllegalStateException("init ServiceSinkhole", e);
        }
    }

    public ServiceSinkhole(Socket socket, List<ProxyVpn> clients, RootCert rootCert, int os) throws IOException {
        super(clients, rootCert);
        InputStream inputStream = socket.getInputStream();
        this.clientOS = readOS(this, new DataInputStream(inputStream), os);

        int mtu = jni_get_mtu();

        this.jni_context = jni_init(30);
        this.socket = socket;
        final int ANDROID_LOG_DEBUG = 3;
        final int ANDROID_LOG_ERROR = 6;
        jni_start(jni_context, log.isTraceEnabled() ? ANDROID_LOG_DEBUG : ANDROID_LOG_ERROR);
        log.debug("mtu={}, socket={}", mtu, socket);
    }

    @Override
    protected synchronized void stop() {
        if (tunnelThread != null) {
            if (log.isDebugEnabled()) {
                log.debug("Stopping tunnel thread: context=0x{}, obj={}", Long.toHexString(jni_context), this);
            }

            jni_stop(jni_context);

            Thread thread = tunnelThread;
            if (thread != null) {
                try {
                    thread.join();
                } catch (InterruptedException ignored) {
                }
            }
            tunnelThread = null;

            log.debug("Stopped tunnel thread");
        }
    }

    private Thread tunnelThread;

    @Override
    public Application[] queryApplications(int hash) {
        Application[] applications = this.applications.get(hash);
        if (applications != null) {
            return applications;
        } else {
            return super.queryApplications(hash);
        }
    }

    private final Map<Integer, Application[]> applications = new HashMap<>();

    private class ApplicationDiscoverHandler implements Runnable, AutoCloseable {
        private final DatagramSocket udp;
        private final SocketAddress socketAddress;
        public ApplicationDiscoverHandler() throws IOException {
            udp = new DatagramSocket();
            udp.setSoTimeout(1500);
            socketAddress = socket.getRemoteSocketAddress();
        }
        private void sendAllowed(Packet packet) {
            packet.sendAllowed(udp, socketAddress);
        }
        @Override
        public void run() {
            byte[] buffer = new byte[1024];
            try {
                while (!canStop) {
                    try {
                        DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                        udp.receive(datagramPacket);
                        DataInput dataInput = new DataInputStream(new ByteArrayInputStream(buffer));
                        int type = dataInput.readUnsignedByte();
                        if (type != 0x2) {
                            throw new IllegalStateException("Invalid type=" + type);
                        }
                        int hash = dataInput.readInt();
                        int size = dataInput.readUnsignedByte();
                        Application[] applications = new Application[size];
                        for (int i = 0; i < size; i++) {
                            applications[i] = Application.decodeApps(dataInput);
                        }
                        ServiceSinkhole.this.applications.put(hash, applications);
                        log.debug("applications={}", ServiceSinkhole.this.applications);
                    } catch (SocketTimeoutException ignored) {
                    }
                }
            } catch (IOException e) {
                log.debug("handle udp", e);
            } catch (Exception e) {
                log.warn("handle udp", e);
            } finally {
                IoUtil.close(this);
            }
        }
        private boolean canStop;
        @Override
        public void close() {
            canStop = true;
            IoUtil.close(udp);
        }
    }

    private ApplicationDiscoverHandler applicationDiscoverHandler;

    @Override
    protected void doRunVpn() {
        try {
            tunnelThread = Thread.currentThread();
            if (!directAllowAll && clientOS == ClientOS.Android) {
                try {
                    applicationDiscoverHandler = new ApplicationDiscoverHandler();
                    executorService.submit(applicationDiscoverHandler);
                } catch (Exception e) {
                    log.debug("create udp failed.", e);
                    IoUtil.close(applicationDiscoverHandler);
                    applicationDiscoverHandler = null;
                }
            }

            log.debug("Vpn thread starting");

            int fd = getFileDescriptorFromSocket(socket);
            log.debug("Running tunnel: fd={}", fd);
            jni_run(jni_context, fd, true, 3);
            log.debug("Tunnel exited");
            IoUtil.close(applicationDiscoverHandler);
            applicationDiscoverHandler = null;

            IoUtil.close(socket);
            log.debug("Vpn thread shutting down");
            applications.clear();

            clients.remove(this);

            tunnelThread = null;

            jni_done(jni_context);

            if (connectionListener != null) {
                connectionListener.notifyVpnStop(this);
            }

            if (packetCapture != null) {
                packetCapture.notifyVpnFinish();
            }
        } catch (Throwable e) {
            log.warn("vpn run", e);
        } finally {
            log.info("client {} vpn closed: {}", clientOS, socket.getRemoteSocketAddress());
        }
    }

    private native long jni_init(int sdk);

    private native void jni_start(long context, int loglevel);

    private native void jni_run(long context, int tun, boolean fwd53, int rcode);

    private native void jni_stop(long context);

    @SuppressWarnings("unused")
    private native void jni_clear(long context);

    private native int jni_get_mtu();

    @SuppressWarnings("unused")
    private native int[] jni_get_stats(long context);

    @SuppressWarnings("unused")
    private static native void jni_pcap(String name, int record_size, int file_size);

    @SuppressWarnings("unused")
    private static native FileDescriptor jni_getFileDescriptorFromSocket(Socket socket);

    @SuppressWarnings("unused")
    private static native int jni_getFd(FileDescriptor fileDescriptor);

    @SuppressWarnings("unused")
    private native void jni_socks5(String addr, int port, String username, String password);

    private native void jni_done(long context);


    // Called from native code
    @SuppressWarnings("unused")
    private void nativeExit(String reason) {
        log.debug("Native exit reason={}", reason);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void nativeError(int error, String message) {
        log.warn("Native error {}: {}", error, message);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void logPacket(Packet packet) {
         log.debug("logPacket packet {}, data={}", packet, packet.data);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void dnsResolved(ResourceRecord rr) {
        log.debug("dnsResolved rr={}", rr);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private boolean isDomainBlocked(String name) {
        log.debug("check block domain name={}", name);
        return false;
    }

    // Called from native code
    @SuppressWarnings("unused")
    private int getUidQ(int version, int protocol, String saddr, int sport, String daddr, int dport) {
        if (protocol != Packet.TCP_PROTOCOL && protocol != Packet.UDP_PROTOCOL) {
            return -1;
        } else {
            return SYSTEM_UID;
        }
    }

    private boolean isSupported(int protocol) {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 59 /* ICMPv6 */ ||
                protocol == Packet.TCP_PROTOCOL ||
                protocol == Packet.UDP_PROTOCOL);
    }

    private static final int SYSTEM_UID = 2000;

    // Called from native code
    @SuppressWarnings("unused")
    private Allowed isAddressAllowed(Packet packet) {
        if (directAllowAll) {
            return new Allowed();
        }
        packet.allowed = false;
        ApplicationDiscoverHandler handler = this.applicationDiscoverHandler;
        if (packet.uid <= SYSTEM_UID && isSupported(packet.protocol)) {
            if (packet.version == Packet.IP_V4 && packet.protocol == Packet.TCP_PROTOCOL) { // tcp ipv4
                if (handler != null) {
                    handler.sendAllowed(packet);
                }
                return redirectTcp(packet);
            }
            if (packet.version == Packet.IP_V4 && packet.protocol == Packet.UDP_PROTOCOL) { // udp ipv4
                return redirectUdp(packet);
            } else if(packet.version == Packet.IP_V6) {
                log.info("Disallow ipv6: packet={}", packet);
            } else {
                log.debug("Disallow packet={}", packet);
            }
            log.debug("isAddressAllowed: packet={}, allowed={}", packet, packet.allowed);
        }

        if (handler != null && packet.allowed) {
            handler.sendAllowed(packet);
        }

        return packet.allowed ? new Allowed() : null;
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void accountUsage(Usage usage) {
         log.debug("accountUsage usage={}", usage);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void notifyConnected(Connected connected) {
        log.trace("notifyConnected connected={}", connected);
        if (connectionListener != null) {
            try {
                connectionListener.notifyConnected(this, connected);
            } catch (Exception e) {
                log.warn("notifyConnected failed", e);
            }
        }
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void notifyDisconnected(Connected connected) {
        log.trace("notifyDisconnected connected={}", connected);
        if(connectionListener != null) {
            try {
                connectionListener.notifyDisconnected(this, connected);
            } catch(Exception e) {
                log.warn("notifyDisconnected failed", e);
            }
        }
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void notifyPacket(int uid, byte[] packet) {
        if (packetCapture != null) {
            packetCapture.onPacket(packet, "NetGuard");
        }
    }

    // Called from native code
    @SuppressWarnings("unused")
    private boolean protect(int fd) {
        return true;
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }
}

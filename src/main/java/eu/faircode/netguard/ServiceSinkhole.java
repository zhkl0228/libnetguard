package eu.faircode.netguard;

import cn.banny.utils.IOUtils;
import com.fuzhu8.tcpcap.PcapDLT;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.InspectorVpn;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.scijava.nativelib.NativeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketImpl;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

public class ServiceSinkhole extends ProxyVpn implements InspectorVpn {

    private static final Logger log = LoggerFactory.getLogger(ServiceSinkhole.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            NativeLoader.loadLibrary("netguard");
        } catch (IOException ignored) {
        }
    }

    private static Method getImpl, getFileDescriptor;
    private static Field fdField;

    private final Socket socket;
    private final long jni_context;
    private final int fd;

    public ServiceSinkhole(Socket socket, List<ProxyVpn> clients) {
        super(clients);
        int mtu = jni_get_mtu();

        this.jni_context = jni_init(30);
        try {
            if (getImpl == null) {
                getImpl = Socket.class.getDeclaredMethod("getImpl");
                getImpl.setAccessible(true);
            }
            if (getFileDescriptor == null) {
                getFileDescriptor = SocketImpl.class.getDeclaredMethod("getFileDescriptor");
                getFileDescriptor.setAccessible(true);
            }
            if (fdField == null) {
                fdField = FileDescriptor.class.getDeclaredField("fd");
                fdField.setAccessible(true);
            }
            SocketImpl impl = (SocketImpl) getImpl.invoke(socket);
            FileDescriptor fileDescriptor = (FileDescriptor) getFileDescriptor.invoke(impl);
            if (!fileDescriptor.valid()) {
                throw new IllegalStateException("Invalid fd: " + fileDescriptor);
            }
            this.fd = (Integer) fdField.get(fileDescriptor);

            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            String alias = "tcpcap-ssl-proxying";
            try (InputStream inputStream = ServiceSinkhole.class.getResourceAsStream("/tcpcap-ssl-proxying.p12")) {
                keyStore.load(inputStream, "tcpcap".toCharArray());
            }
            rootCert = (X509Certificate) keyStore.getCertificate(alias);
            privateKey = (PrivateKey) keyStore.getKey(alias, null);
        } catch (Exception e) {
            throw new IllegalStateException("init ServiceSinkhole", e);
        }
        this.socket = socket;
        final int ANDROID_LOG_DEBUG = 3;
        final int ANDROID_LOG_ERROR = 6;
        jni_start(jni_context, log.isTraceEnabled() ? ANDROID_LOG_DEBUG : ANDROID_LOG_ERROR);
        log.debug("mtu={}, socket={}, fd={}", mtu, socket, fd);
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

            jni_clear(jni_context);

            log.debug("Stopped tunnel thread");
        }
    }

    private Thread tunnelThread;

    @Override
    public void run() {
        tunnelThread = Thread.currentThread();

        log.debug("Vpn thread starting");

        log.debug("Running tunnel");
        jni_run(jni_context, fd, false, 3);
        log.debug("Tunnel exited");

        IOUtils.close(socket);
        log.debug("Vpn thread shutting down");

        clients.remove(this);

        tunnelThread = null;

        jni_done(jni_context);
    }

    private native long jni_init(int sdk);

    private native void jni_start(long context, int loglevel);

    private native void jni_run(long context, int tun, boolean fwd53, int rcode);

    private native void jni_stop(long context);

    private native void jni_clear(long context);

    private native int jni_get_mtu();

    @SuppressWarnings("unused")
    private native int[] jni_get_stats(long context);

    @SuppressWarnings("unused")
    private static native void jni_pcap(String name, int record_size, int file_size);

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
        log.info("dnsResolved rr={}", rr);
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
        if (protocol != 6 /* TCP */ && protocol != 17 /* UDP */)
            return -1;

        InetSocketAddress local = new InetSocketAddress(saddr, sport);
        InetSocketAddress remote = new InetSocketAddress(daddr, dport);

        int uid = SYSTEM_UID; // cm.getConnectionOwnerUid(protocol, local, remote);
        log.debug("Get uid local={} remote={}, uid={}", local, remote, uid);
        return uid;
    }

    private boolean isSupported(int protocol) {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 59 /* ICMPv6 */ ||
                protocol == 6 /* TCP */ ||
                protocol == 17 /* UDP */);
    }

    private int[] sslPorts;

    @Override
    public void enableMitm(int... sslPorts) {
        this.sslPorts = sslPorts;
    }

    private static final int SYSTEM_UID = 2000;

    // Called from native code
    @SuppressWarnings("unused")
    private Allowed isAddressAllowed(Packet packet) {
        packet.allowed = false;
        if (packet.uid <= SYSTEM_UID && isSupported(packet.protocol)) {
            // Allow unknown system traffic
            packet.allowed = true;
            log.debug("Allowing unknown system {}", packet);
        }

        Allowed allowed = null;
        long start = System.currentTimeMillis();
        try {
            if(packet.allowed) {
                allowed = new Allowed();

                if (packet.protocol == 6 && packet.version == 4
                        && sslPorts != null
                        && packet.isSSL(sslPorts)) { // ipv4
                    allowed = mitm(packet);
                }
            }
        } catch (Exception e) {
            log.warn("mitm failed: {}", packet, e);
        }

        if (allowed != null) {
            if (packet.protocol != 6 /* TCP */ || !"".equals(packet.flags)) {
                logPacket(packet);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("isAddressAllowed allowed={}, packet: {}, offset={}ms", allowed, packet, (System.currentTimeMillis() - start));
        }

        return allowed;
    }

    private final X509Certificate rootCert;
    private final PrivateKey privateKey;

    private Allowed mitm(Packet packet) {
        int mitmTimeout = 10000; // default 10 seconds;
        return SSLProxy.create(this, rootCert, privateKey, packet, mitmTimeout);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void accountUsage(Usage usage) {
         log.debug("accountUsage usage={}", usage);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void notifyPacket(int uid, byte[] packet) {
        if (packetCapture != null) {
            packetCapture.onPacket(packet, "Netguard", PcapDLT.CONST_RAW_IP);
        }
    }

    // Called from native code
    @SuppressWarnings("unused")
    private boolean protect(int fd) {
        log.debug("protect fd={}", fd);
        return true;
    }

}

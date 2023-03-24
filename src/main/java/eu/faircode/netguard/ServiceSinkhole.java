package eu.faircode.netguard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

public class ServiceSinkhole {

    private static final Logger log = LoggerFactory.getLogger(ServiceSinkhole.class);

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
        log.warn("Native exit reason={}", reason);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void nativeError(int error, String message) {
        log.warn("Native error {}: {}", error, message);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void logPacket(Packet packet) {
        // Log.d(TAG, "logPacket packet " + packet + ", data=" + packet.data);
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
    private int getUidQ(int version, int protocol, String saddr, int sport, String daddr, int dport) {
        if (protocol != 6 /* TCP */ && protocol != 17 /* UDP */)
            return -1;

        InetSocketAddress local = new InetSocketAddress(saddr, sport);
        InetSocketAddress remote = new InetSocketAddress(daddr, dport);

        int uid = SYSTEM_UID; // cm.getConnectionOwnerUid(protocol, local, remote);
        log.info("Get uid local={} remote={}, uid={}", local, remote, uid);
        return uid;
    }

    private boolean isSupported(int protocol) {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 59 /* ICMPv6 */ ||
                protocol == 6 /* TCP */ ||
                protocol == 17 /* UDP */);
    }

    private static final int SYSTEM_UID = 2000;

    // Called from native code
    @SuppressWarnings("unused")
    private Allowed isAddressAllowed(Packet packet) {
        packet.allowed = false;
        if (packet.uid <= SYSTEM_UID && isSupported(packet.protocol)) {
            // Allow unknown system traffic
            packet.allowed = true;
            // Log.w(TAG, "Allowing unknown system " + packet);
        }

        Allowed allowed = null;
        long start = System.currentTimeMillis();
        try {
            if (packet.allowed) {
                if (packet.protocol == 6 && packet.version == 4 && packet.isSSL(new int[] { 443 })) { // ipv4
                    allowed = mitm(packet);
                }
            }
        } catch (Exception e) {
            log.debug("mitm failed: {}", packet, e);
        }

        if (allowed != null) {
            if (packet.protocol != 6 /* TCP */ || !"".equals(packet.flags)) {
                logPacket(packet);
            }
        }

        log.debug("isAddressAllowed allowed={}, packet: {}, offset={}ms", allowed, packet, (System.currentTimeMillis() - start));

        return allowed;
    }

    private Allowed mitm(Packet packet) {
        // return SSLProxy.create(this, rootCert, privateKey, packet, mitmTimeout);
        return new Allowed();
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void accountUsage(Usage usage) {
        // Log.d(TAG, "accountUsage usage=" + usage);
    }

    // Called from native code
    @SuppressWarnings("unused")
    private void notifyPacket(int uid, byte[] packet) {
    }

}

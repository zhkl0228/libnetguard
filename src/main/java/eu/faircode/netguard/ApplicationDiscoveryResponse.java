package eu.faircode.netguard;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Objects;

/**
 * A client's answer to an application discovery query ({@link Packet#sendAllowed}), keyed like {@link Packet#hashCode()}.
 */
class ApplicationDiscoveryResponse {

    /**
     * Android, from AndroidVPN InspectorVpnService.ApplicationDiscoverServer:
     * {@code u8 0x2, i32 hash, u8 count, count * (UTF packageName, UTF label, i64 versionCode)}
     */
    private static final int ANDROID = 0x2;

    /**
     * iOS, from inspectorvpnd ({@code ios/inspectorvpnd}) on jailbroken devices:
     * {@code u8 0x3, u8 protocol, UTF saddr, u16 sport, UTF daddr, u16 dport, owner} with the owner as in
     * {@link IOSApplication#decodeOwner}
     */
    private static final int IOS = 0x3;

    static ApplicationDiscoveryResponse decode(byte[] data) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream in = new DataInputStream(bais);
        int type = in.readUnsignedByte();
        ApplicationDiscoveryResponse response;
        switch (type) {
            case ANDROID: {
                int hash = in.readInt();
                Application[] applications = new Application[in.readUnsignedByte()];
                for (int i = 0; i < applications.length; i++) {
                    applications[i] = Application.decodeApps(in);
                }
                response = new ApplicationDiscoveryResponse(hash, applications);
                break;
            }
            case IOS: {
                int protocol = in.readUnsignedByte();
                String saddr = in.readUTF();
                int sport = in.readUnsignedShort();
                String daddr = in.readUTF();
                int dport = in.readUnsignedShort();
                Application[] applications = new Application[]{IOSApplication.decodeOwner(in)};
                response = new ApplicationDiscoveryResponse(Objects.hash(protocol, saddr, sport, daddr, dport), applications);
                break;
            }
            default:
                throw new IOException("Unknown application discovery response type 0x" + Integer.toHexString(type));
        }
        if (bais.available() != 0) {
            throw new IOException(bais.available() + " trailing bytes after application discovery response type 0x" + Integer.toHexString(type));
        }
        return response;
    }

    final int hash;
    final Application[] applications;

    private ApplicationDiscoveryResponse(int hash, Application[] applications) {
        this.hash = hash;
        this.applications = applications;
    }
}

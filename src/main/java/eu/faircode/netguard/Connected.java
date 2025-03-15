package eu.faircode.netguard;

import java.net.InetSocketAddress;
import java.util.Date;
import java.util.Objects;

public class Connected implements Comparable<Connected> {

    public enum IPVersion {
        ipv4, ipv6, unknown
    }
    public enum IPProtocol {
        tcp, udp, unknown
    }

    private long Time;
    private int Version;
    private int Protocol;
    private String SAddr;
    private int SPort;
    private String DAddr;
    private int DPort;
    private int LPort;

    public Date getEventDate() {
        return new Date(Time);
    }

    public IPVersion getVersion() {
        switch (Version) {
            case Packet.IP_V4:
                return IPVersion.ipv4;
            case Packet.IP_V6:
                return IPVersion.ipv6;
            default:
                return IPVersion.unknown;
        }
    }

    public IPProtocol getProtocol() {
        switch (Protocol) {
            case Packet.TCP_PROTOCOL:
                return IPProtocol.tcp;
            case Packet.UDP_PROTOCOL:
                return IPProtocol.udp;
            default:
                return IPProtocol.unknown;
        }
    }

    public InetSocketAddress getSourceAddress() {
        return new InetSocketAddress(SAddr, SPort);
    }

    public InetSocketAddress getDestinationAddress() {
        return new InetSocketAddress(DAddr, DPort);
    }

    public int getLocalPort() {
        return LPort;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Connected connected = (Connected) o;
        return Version == connected.Version && Protocol == connected.Protocol && SPort == connected.SPort && DPort == connected.DPort && Objects.equals(SAddr, connected.SAddr) && Objects.equals(DAddr, connected.DAddr);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Version, Protocol, SAddr, SPort, DAddr, DPort);
    }

    @Override
    public int compareTo(Connected o) {
        return getEventDate().compareTo(o.getEventDate());
    }

    @Override
    public String toString() {
        return getVersion() + " " + getProtocol() +
                " " + getSourceAddress() + " => " + getDestinationAddress() +
                " Local: " + getLocalPort();
    }

}

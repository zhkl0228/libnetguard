package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2018 by Marcel Bokhorst (M66B)
*/

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.Objects;

public class Packet {

    private static final Logger log = LoggerFactory.getLogger(Packet.class);

    public static final int IP_V4 = 4;
    public static final int IP_V6 = 6;
    public static final int TCP_PROTOCOL = 6;
    public static final int UDP_PROTOCOL = 17;

    public long time;
    public int version;
    public int protocol;
    public String flags;
    public String saddr;
    public int sport;
    public String daddr;
    public int dport;
    public String data;
    public int uid;
    @SuppressWarnings("unused")
    public byte[] payload;
    public boolean allowed;

    public Packet() {
        super();
    }

    public boolean isInstallRootCert() {
        return "88.88.88.88".equals(daddr) && dport == 88;
    }

    public InetSocketAddress createClientAddress() {
        try {
            return new InetSocketAddress(InetAddress.getByName(saddr), sport);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("createClientAddress daddr=" + daddr + ", dport=" + dport, e);
        }
    }

    public InetSocketAddress createServerAddress() {
        try {
            return new InetSocketAddress(InetAddress.getByName(daddr), dport);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("createServerAddress daddr=" + daddr + ", dport=" + dport, e);
        }
    }

    @Override
    public String toString() {
        return "uid=" + uid + " v" + version + " p" + protocol + " " + saddr + "/" + sport + " => " + daddr + "/" + dport + ", flags=" + flags;
    }

    public void sendAllowed(DatagramSocket udp, SocketAddress address) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeByte(0x1);
            dataOutput.writeByte(protocol);
            dataOutput.writeUTF(saddr);
            dataOutput.writeShort(sport);
            dataOutput.writeUTF(daddr);
            dataOutput.writeShort(dport);
            byte[] data = baos.toByteArray();
            log.debug("sendAllowed packet={}, address={}", this, address);
            udp.send(new DatagramPacket(data, data.length, address));
        } catch (IOException e) {
            log.warn("sendAllowed address={}", address, e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Packet packet = (Packet) o;
        return protocol == packet.protocol && sport == packet.sport && dport == packet.dport && Objects.equals(saddr, packet.saddr) && Objects.equals(daddr, packet.daddr);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocol, saddr, sport, daddr, dport);
    }

}

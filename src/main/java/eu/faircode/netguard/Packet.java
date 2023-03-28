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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class Packet {

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

    public String hostName;

    public Packet() {
        super();
    }

    final boolean isSSL(int[] sslPorts) {
        if (sslPorts == null) {
            throw new IllegalArgumentException("sslPorts is NULL.");
        }
        if (sslPorts.length == 0) {
            return dport == 443;
        }
        for (int port : sslPorts) {
            if (port == dport) {
                return true;
            }
        }
        return false;
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
        return "uid=" + uid + " v" + version + " p" + protocol + " " + saddr + "/" + sport + " => " + daddr + "/" + dport;
    }

}

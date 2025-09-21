package com.github.netguard.proxy;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SocksProxyVpn extends ProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(SocksProxyVpn.class);

    private final Socket socket;
    private final ClientOS clientOS;

    public SocksProxyVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert,
                         ClientOS clientOS) {
        super(clients, rootCert);

        this.socket = socket;
        this.clientOS = clientOS;
    }

    private static class Result {
        final Packet packet;
        Result(Packet packet) {
            this.packet = packet;
        }
        void notifyConnected(Socket socket) throws IOException {
            log.debug("notifyConnected: {}", socket);
        }
    }

    private Result handleV5(DataInputStream dis, OutputStream outputStream) throws IOException {
        DataOutputStream dos = new DataOutputStream(outputStream);

        byte methods = dis.readByte();
        for(int i = 0; i < methods; i++) {
            dis.readByte();
        }
        dos.write(new byte[] { 0x5, 0x0 }); // no auth
        dos.flush();

        byte v = dis.readByte();
        if (v != 5) {
            throw new IOException("Unsupported handleConnect version: " + v);
        }

        byte ip = dis.readByte();
        if(ip != 1) {
            throw new IOException("Unsupported ip version type: " + ip);
        }

        dis.readByte();//0

        Packet packet = new Packet();
        byte addrType = dis.readByte();
        if(addrType == 3) {//host
            byte[] hb = new byte[dis.readUnsignedByte()];
            dis.readFully(hb);
            String host = new String(hb, StandardCharsets.UTF_8);
            int port = dis.readUnsignedShort();

            packet.daddr = host;
            packet.dport = port;
        } else if(addrType == 1) {//address
            byte[] ipv4 = new byte[4];
            dis.readFully(ipv4);
            int port = dis.readUnsignedShort();

            InetAddress address = InetAddress.getByAddress(ipv4);
            packet.daddr = address.getHostAddress();
            packet.dport = port;
        } else if (addrType == 4) {
            throw new IOException("Unsupported ipv6");
        } else {
            throw new IOException("Unsupported tcp address type: " + addrType);
        }

        dos.writeInt(0x5000001);
        dos.write(new byte[4]); // ipv4
        dos.writeShort(0);
        dos.flush();

        return new Result(packet);
    }

    private Result handleConnectV4(DataInputStream dis, OutputStream outputStream) throws IOException {
        DataOutputStream dos = new DataOutputStream(outputStream);

        byte cd = dis.readByte();
        if(cd != 1) {
            throw new IOException("Unsupported socks CONNECT type: " + cd);
        }

        int port = dis.readUnsignedShort();

        byte[] ipv4 = new byte[4];
        dis.readFully(ipv4);

        ByteArrayOutputStream baos = new ByteArrayOutputStream(32);
        byte b;
        while((b = dis.readByte()) != 0) {
            baos.write(b);
        }
        String user = baos.toString(StandardCharsets.UTF_8);
        log.debug("handleV4 user={}", user);

        Packet packet = new Packet();
        packet.dport = port;
        if(ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 0) { // socks_v4a
            baos.reset();
            while((b = dis.readByte()) != 0) {
                baos.write(b);
            }
            packet.daddr = baos.toString(StandardCharsets.UTF_8);
        } else { // socksv4
            InetAddress address = InetAddress.getByAddress(ipv4);
            packet.daddr = address.getHostAddress();
        }

        dos.writeShort(0x5a);
        dos.writeShort(0);
        dos.write(new byte[4]); // ipv4
        dos.flush();

        return new Result(packet);
    }

    @Override
    protected void doRunVpn() {
        try {
            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();
            DataInputStream dis = new DataInputStream(inputStream);
            final Result result;
            switch (clientOS) {
                case SocksV4:
                    result = handleConnectV4(dis, outputStream);
                    break;
                case SocksV5:
                    result = handleV5(dis, outputStream);
                    break;
                default:
                    throw new IllegalStateException("clientOS=" + clientOS);
            }
            SSLProxyV2.create(this, result.packet, 10000, socket, result::notifyConnected);
        } catch (IOException e) {
            log.debug("handle socks failed.", e);
            IoUtil.close(socket);
        } catch (Exception e) {
            log.warn("handle socks exception.", e);
            IoUtil.close(socket);
        }
    }

    @Override
    protected void stop() {
        IoUtil.close(socket);
    }

    @Override
    public final ClientOS getClientOS() {
        return clientOS;
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

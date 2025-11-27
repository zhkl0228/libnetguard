package com.github.netguard.proxy;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.FallbackProxyVpn;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class TrojanProxyVpn extends FallbackProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(TrojanProxyVpn.class);

    private final InputStream inputStream;

    public TrojanProxyVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, InputStream inputStream) {
        super(socket, clients, rootCert);
        this.inputStream = inputStream;
    }

    @Override
    protected void doRunVpn() {
        try {
            DataInput dataInput = new DataInputStream(inputStream);
            byte[] passwd = new byte[56];
            dataInput.readFully(passwd);
            dataInput.skipBytes(2);

            int type = dataInput.readUnsignedByte();
            if (type == 1) { // Tcp connect
                int addressType = dataInput.readUnsignedByte();
                Packet packet = new Packet();
                switch (addressType) {
                    case 0x1: { // IPv4
                        byte[] ipv4 = new byte[4];
                        dataInput.readFully(ipv4);
                        int port = dataInput.readUnsignedShort();

                        InetAddress address = InetAddress.getByAddress(ipv4);
                        packet.daddr = address.getHostAddress();
                        packet.dport = port;
                        break;
                    }
                    case 0x3: { // domain
                        byte[] hb = new byte[dataInput.readUnsignedByte()];
                        dataInput.readFully(hb);
                        String host = new String(hb, StandardCharsets.UTF_8);
                        int port = dataInput.readUnsignedShort();

                        packet.daddr = host;
                        packet.dport = port;
                        break;
                    }
                    case 0x4: // IPv6
                    default:
                        throw new IllegalStateException("Invalid address type=" + addressType);
                }

                dataInput.skipBytes(2);
                log.debug("doRunVpn connect packet={}", packet);
                SSLProxyV2.create(this, packet, 10000, socket, null, inputStream);
                return;
            }
            throw new UnsupportedOperationException("NOT support trojan proxy: type=" + type);
        } catch (Exception e) {
            log.warn("handle trajan proxy", e);
            IoUtil.close(socket);
        }
    }

    @Override
    public final ClientOS getClientOS() {
        return ClientOS.TrojanProxy;
    }

}

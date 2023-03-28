package com.github.netguard.vpn.ssl;

import cn.banny.auxiliary.Inspector;
import com.fuzhu8.tcpcap.kraken.ssl.ExtensionType;
import com.fuzhu8.tcpcap.kraken.ssl.Version;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.DefaultHandshake;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.Handshake;
import com.fuzhu8.tcpcap.kraken.ssl.handshake.HandshakeType;
import com.fuzhu8.tcpcap.kraken.ssl.record.ContentType;
import org.apache.commons.codec.binary.Hex;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

class ExtensionServerName {

    private static final Logger log = LoggerFactory.getLogger(ExtensionServerName.class);

    private static Version getVersion(short version) {
        Version tlsVer = Version.NONE;
        for (Version ver : Version.values()) {
            if (ver.getValue() == version) {
                tlsVer = ver;
                break;
            }
        }
        return tlsVer;
    }

    static ClientHelloRecord parseServerNames(DataInput dataInput, InetSocketAddress server) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutput dataOutput = new DataOutputStream(baos);
        byte contentType = dataInput.readByte();
        dataOutput.writeByte(contentType);
        if (contentType != ContentType.Handshake.getValue()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Not handshake record: contentType=0x%x, server=%s", contentType, server));
            }
            return new ClientHelloRecord(baos);
        }
        short version = dataInput.readShort();
        dataOutput.writeShort(version);
        Version recordVersion = getVersion(version);
        if (recordVersion == Version.NONE || recordVersion == Version.MM_TLS) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Tls version=0x%x, server=%s", version, server));
            }
            return new ClientHelloRecord(baos);
        }
        int length = dataInput.readUnsignedShort();
        dataOutput.writeShort(length);
        if(length >= 0x800) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Tls length=0x%x, server=%s", length, server));
            }
            return new ClientHelloRecord(baos);
        }

        byte[] clientHelloData = new byte[length];
        dataInput.readFully(clientHelloData);
        dataOutput.write(clientHelloData);
        Handshake handshake;
        try {
            handshake = DefaultHandshake.parseHandshake(new ChainBuffer(clientHelloData));
        } catch (IllegalArgumentException e) {
            log.debug("Not tls: server={}", server, e);
            return new ClientHelloRecord(baos);
        }
        if (handshake.getType() != HandshakeType.ClientHello) {
            log.debug("Not tls: handshakeType={}, server={}", handshake.getType(), server);
            return new ClientHelloRecord(baos);
        }

        Buffer buffer = handshake.getBuffer();
        version = buffer.getShort();
        Version tlsVer = getVersion(version);
        if (tlsVer == Version.NONE || tlsVer == Version.MM_TLS) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Tls handshake version=0x%x, server=%s", version, server));
            }
            return new ClientHelloRecord(baos);
        }
        buffer.skip(32); // clientRandom
        buffer.skip(buffer.get() & 0xff); // sessionId
        buffer.skip(buffer.getUnsignedShort()); // skip cipher suites
        buffer.skip(buffer.get()); // compression methods
        if (buffer.readableBytes() < 2) {
            log.debug("Not tls: extension data is empty: server={}", server);
            return new ClientHelloRecord(baos);
        }
        int extensionLength = buffer.getUnsignedShort();
        byte[] extensionData = new byte[extensionLength];
        buffer.gets(extensionData);

        buffer = new ChainBuffer(extensionData); // extensionData
        List<String> serverNames = new ArrayList<>(2);
        while (buffer.readableBytes() > 0) {
            short type = buffer.getShort();
            length = buffer.getUnsignedShort();
            byte[] data = new byte[length];
            buffer.gets(data);

            if (type == ExtensionType.EXT_SERVER_NAME.getType()) {
                Buffer nb = new ChainBuffer(data);
                nb.getUnsignedShort(); // name length
                byte nameType = nb.get();
                if (nameType == 0) {
                    int nameLength = nb.getUnsignedShort();
                    String name = nb.getString(nameLength, StandardCharsets.UTF_8);
                    serverNames.add(name);
                } else {
                    log.warn("Unsupported name type: {}, data={}, server={}", nameType, Hex.encodeHexString(data), server);
                }
            }
            if (log.isDebugEnabled()) {
                log.trace(Inspector.inspectString(data, "parseExtensions type=0x" + Integer.toHexString(type) + ", length=" + length));
            }
        }
        log.debug("parseExtensions names={}, server={}", serverNames, server);

        if (serverNames.isEmpty()) {
            log.debug("Not tls: extension name is empty: server={}", server);
            return new ClientHelloRecord(baos);
        } else {
            String hostName = serverNames.get(0);
            return new ClientHelloRecord(baos, hostName);
        }
    }

}

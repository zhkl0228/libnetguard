package com.github.netguard.vpn.tcp;

import cn.hutool.core.util.HexUtil;
import com.github.netguard.Inspector;
import com.github.netguard.vpn.tls.CipherSuite;
import com.github.netguard.vpn.tls.JA3Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ExtensionServerName {

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

    public static ClientHelloRecord parseServerNames(DataInputStream dataInput, InetSocketAddress server) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutput dataOutput = new DataOutputStream(baos);
        byte contentType = dataInput.readByte();
        dataOutput.writeByte(contentType);
        if (contentType != ContentType.Handshake.getValue()) {
            if (log.isDebugEnabled()) {
                log.debug("{}", String.format("Not handshake record: contentType=0x%x, server=%s", contentType, server));
            }
            return ClientHelloRecord.prologue(baos, dataInput);
        }
        short version = dataInput.readShort();
        dataOutput.writeShort(version);
        Version recordVersion = getVersion(version);
        if (recordVersion == Version.NONE) {
            if (log.isDebugEnabled()) {
                log.debug("{}", String.format("Tls version=0x%x, server=%s", version, server));
            }
            return ClientHelloRecord.prologue(baos, dataInput);
        }
        int length = dataInput.readUnsignedShort();
        dataOutput.writeShort(length);
        if(length > 0x1200) {
            if (log.isDebugEnabled()) {
                log.debug("{}", String.format("Tls length=0x%x, server=%s", length, server));
            }
            return ClientHelloRecord.prologue(baos, dataInput);
        }

        byte[] clientHelloData = new byte[length];
        dataInput.readFully(clientHelloData);
        dataOutput.write(clientHelloData);
        Handshake handshake = HandshakeParser.parseHandshake(ByteBuffer.wrap(clientHelloData));
        if (handshake.getType() != HandshakeType.ClientHello) {
            log.debug("Not tls: handshakeType={}, server={}", handshake.getType(), server);
            return ClientHelloRecord.prologue(baos, dataInput);
        }

        ByteBuffer buffer = handshake.getBuffer();
        version = buffer.getShort();
        Version tlsVer = getVersion(version);
        if (tlsVer == Version.NONE) {
            if (log.isDebugEnabled()) {
                log.debug("{}", String.format("Tls handshake version=0x%x, server=%s", version, server));
            }
            return ClientHelloRecord.prologue(baos, dataInput);
        }
        buffer.get(new byte[32]); // clientRandom
        buffer.get(new byte[buffer.get() & 0xff]); // sessionId
        int cipherSuiteCount = (buffer.getShort() & 0xffff) / 2;
        List<CipherSuite> cipherSuites = new ArrayList<>(cipherSuiteCount);
        for(int i = 0; i < cipherSuiteCount; i++) {
            int value = buffer.getShort() & 0xffff;
            if(JA3Signature.isNotGrease(value)) {
                CipherSuite cipherSuite = CipherSuite.valueOf(value);
                if (cipherSuite != null) {
                    cipherSuites.add(cipherSuite);
                }
            }
        }
        buffer.get(new byte[buffer.get() & 0xff]); // compression methods
        if (buffer.remaining() < 2) {
            log.debug("Not tls: extension data is empty: server={}", server);
            return ClientHelloRecord.prologue(baos, dataInput);
        }
        int extensionLength = buffer.getShort() & 0xffff;
        byte[] extensionData = new byte[extensionLength];
        buffer.get(extensionData);

        buffer = ByteBuffer.wrap(extensionData); // extensionData
        List<String> serverNames = new ArrayList<>(2);
        List<String> applicationLayerProtocols = new ArrayList<>(2);
        boolean hasSignatureAlgorithms = false;
        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            length = buffer.getShort() & 0xffff;
            byte[] data = new byte[length];
            buffer.get(data);

            if (type == 0) { // EXT_SERVER_NAME
                ByteBuffer nb = ByteBuffer.wrap(data);
                nb.getShort(); // name length
                byte nameType = nb.get();
                if (nameType == 0) {
                    int nameLength = nb.getShort() & 0xffff;
                    byte[] nameData = new byte[nameLength];
                    nb.get(nameData);
                    String name = new String(nameData, StandardCharsets.UTF_8);
                    serverNames.add(name);
                } else {
                    log.warn("Unsupported name type: {}, data={}, server={}", nameType, HexUtil.encodeHexStr(data), server);
                }
            } else if (type == 0x10) { // ALPN
                ByteBuffer nb = ByteBuffer.wrap(data);
                nb.getShort(); // ALPN length
                while (nb.hasRemaining()) {
                    int len = nb.get() & 0xff;
                    byte[] alpnData = new byte[len];
                    nb.get(alpnData);
                    String alpn = new String(alpnData, StandardCharsets.UTF_8);
                    applicationLayerProtocols.add(alpn);
                }
            } else if (type == 0xd) {
                hasSignatureAlgorithms = true;
            }
            if (log.isDebugEnabled()) {
                log.trace(Inspector.inspectString(data, "parseExtensions type=0x" + Integer.toHexString(type) + ", length=" + length));
            }
        }
        byte[] prologue = baos.toByteArray();
        String hostName = serverNames.isEmpty() ? null : serverNames.get(0);
        JA3Signature ja3 = JA3Signature.parse(ByteBuffer.wrap(prologue), hostName, applicationLayerProtocols);
        log.debug("parseExtensions names={}, server={}, applicationLayerProtocols={}, hasSignatureAlgorithms={}, ja3={}", serverNames, server, applicationLayerProtocols, hasSignatureAlgorithms, ja3);

        if (hostName != null || (hasSignatureAlgorithms && !cipherSuites.isEmpty())) {
            return new ClientHelloRecord(prologue, hostName, applicationLayerProtocols, null, ja3, cipherSuites, true);
        } else {
            log.debug("Not tls: extension name is empty: server={}", server);
            return ClientHelloRecord.prologue(baos, dataInput, ja3);
        }
    }

}

/**
 *  Copyright 2019, Oath Inc.
 *  Licensed under the terms of the Apache 2.0 license.
 *  See LICENSE file in {@link https://github.com/lafaspot/ja3_4java/blob/master/LICENSE} for terms.
 */
package com.github.netguard.vpn.tls;

import cn.hutool.crypto.digest.DigestUtil;
import com.github.netguard.vpn.Vpn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.agent15.TlsConstants;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates JA3 signature based on the implementation described at <a href="https://github.com/salesforce/ja3">ja3</a>.
 *
 */
public final class JA3Signature implements TlsSignature {

    private static final Logger log = LoggerFactory.getLogger(JA3Signature.class);

    /**
     * Handshake identifier.
     */
    private static final byte HANDSHAKE = 22;

    /**
     * Client hello.
     */
    private static final byte CLIENT_HELLO = 1;

    /**
     * Client hello random length.
     */
    private static final byte CLIENT_HELLO_RANDOM_LEN = 32;

    /**
     * Minimum packet length to build JA3 signature.
     */
    private static final int MIN_PACKET_LENGTH = 4;

    /**
     * Number of bytes used to identify the SSL Version Length in payload.
     */
    private static final int SSL_VERSION_LENGTH = 3;

    /**
     * Number of bits in byte.
     */
    private static final int ONE_BYTE = 8;

    /**
     * Number of bits in 2 bytes.
     */
    private static final int TWO_BYTES = 16;

    /**
     * Bytes in 16 bit unsigned integer.
     */
    private static final int UINT16_LENGTH = 2;

    /**
     * Bytes in 24 bit unsigned integer.
     */
    private static final int UINT24_LENGTH = 3;

    /**
     * Vertical Tab character.
     */
    static final byte TYPE_ELLIPTIC_CURVE_POINT_FORMATS = 0x0b;

    /**
     * Byte bit mask.
     */
    private static final int BITMASK = 0xFF;

    /**
     * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described here:
     * <a href="https://tools.ietf.org/html/draft-davidben-tls-grease-01">draft-davidben-tls-grease-01</a>.
     */
    private static final int[] GREASE = new int[] { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa };

    /**
     * Calculate JA3 string from a ClientHello packet.Note that we do not compute an MD5 hash here.
     *
     * @param packet                    packet to inspect
     * @return JA3 fingerprint or null if no TLS ClientHello detected in given packet
     * @see <a href="https://github.com/salesforce/ja3">Original JA3 implementation</a>
     */
    public static JA3Signature parse(ByteBuffer packet, String hostName, List<String> applicationLayerProtocols) {
        // Check there is enough remaining to be able to read TLS record header
        if (packet.remaining() < MIN_PACKET_LENGTH) {
            return null;
        }

        try {
            int end = packet.remaining() + packet.position(); // non-inclusive
            int off = packet.position();

            final byte messageType = getByte(packet, off, end);
            off += SSL_VERSION_LENGTH; // skip TLS Major/Minor

            if (messageType != HANDSHAKE) {
                return null; // not a handshake message
            }

            final int length = getUInt16(packet, off, end);
            off += UINT16_LENGTH;

            if (end < off + length) {
                return null; // buffer underflow
            }
            // ensure if TLS message length is smaller than packet length, we don't read over
            end = off + length;

            final byte handshakeType = getByte(packet, off, end);
            off++;

            if (handshakeType != CLIENT_HELLO) {
                // log.trace("TLS handshake type not clienthello: {}", handshakeType);
                return null; // not client_hello
            }

            final int handshakeLength = getUInt24(packet, off, end);
            off += SSL_VERSION_LENGTH;

            if (end < off + handshakeLength) {
                return null; // buffer underflow
            }
            // ensure if handShakeLength is smaller than TLS message length, we don't read over
            end = off + handshakeLength;

            final int clientVersion = getUInt16(packet, off, end);
            // Skip random
            off += UINT16_LENGTH + CLIENT_HELLO_RANDOM_LEN;

            off += packet.get(off) + 1; // Skip Session ID

            final int cipherSuiteLength = getUInt16(packet, off, end);
            off += UINT16_LENGTH;

            if (cipherSuiteLength % 2 != 0) {
                return null; // invalid packet, cipher suite length must always be even
            }

            List<Integer> cipherSuites = new ArrayList<>();
            convertUInt16ArrayToJa3(packet, off, off + cipherSuiteLength, cipherSuites);
            off += cipherSuiteLength;

            final int compressionLength = packet.get(off) & 0xff;
            off++;
            final List<Integer> compressionMethods = new ArrayList<>(compressionLength);
            for(int i = 0; i < compressionLength; i++) {
                compressionMethods.add(packet.get(off + i) & 0xff);
            }
            off += compressionLength + UINT16_LENGTH;

            final List<Integer> ec = new ArrayList<>(); // elliptic curves
            final List<Integer> ecpf = new ArrayList<>(); // elliptic curve point formats
            final List<Integer> signatureAlgorithms = new ArrayList<>();
            Map<Integer, byte[]> extensionTypes = parseExtensions(packet, off, end, ec, ecpf, signatureAlgorithms);
            return new JA3Signature(new LegacyClientHello(clientVersion, cipherSuites, extensionTypes, ec, ecpf, signatureAlgorithms,
                    hostName, applicationLayerProtocols, compressionMethods));
        } catch (BufferUnderflowException | ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    private final ClientHello clientHello;

    public JA3Signature(ClientHello clientHello) {
        this.clientHello = clientHello;
    }

    private Map<Integer, byte[]> createExtensionTypesWithoutGrease() {
        Map<Integer, byte[]> extensionTypes = new LinkedHashMap<>(clientHello.getExtensionTypes());
        for (Integer grease : GREASE) {
            extensionTypes.remove(grease);
        }
        return extensionTypes;
    }

    private List<Integer> createCipherSuitesWithoutGrease() {
        List<Integer> cipherSuites = new ArrayList<>(clientHello.getCipherSuites());
        for (Integer grease : GREASE) {
            cipherSuites.remove(grease);
        }
        return cipherSuites;
    }

    private static final String GREASE_TEXT = "GREASE";

    @Override
    public String getPeetPrintText() {
        StringBuilder peetPrint = new StringBuilder();
        {
            byte[] supportedVersions = clientHello.getExtensionTypes().get(TlsConstants.ExtensionType.supported_versions.value & 0xffff);
            List<Integer> list = new ArrayList<>(5);
            if(supportedVersions != null) {
                ByteBuffer buffer = ByteBuffer.wrap(supportedVersions);
                int length = buffer.get() & 0xff;
                convertUInt16ArrayToJa3(buffer, 1, length + 1, list);
            }
            appendPeerPrintIntegers(peetPrint, list, false);
        }
        {
            List<String> list = createApplicationLayerProtocols();
            peetPrint.append(String.join("-", list)).append("|");
        }
        appendPeerPrintIntegers(peetPrint, clientHello.getEllipticCurves(), false);
        appendPeerPrintIntegers(peetPrint, clientHello.getSignatureAlgorithms(), false);
        {
            byte[] pskSharedMode = clientHello.getExtensionTypes().get(TlsConstants.ExtensionType.psk_key_exchange_modes.value & 0xffff);
            if(pskSharedMode != null && pskSharedMode.length == 2) {
                peetPrint.append(pskSharedMode[1] & 0x1);
            }
            peetPrint.append("|");
        }
        {
            List<Integer> list = new ArrayList<>();
            byte[] compressCertificate = clientHello.getExtensionTypes().get(0x1b);
            if (compressCertificate != null) {
                ByteBuffer buffer = ByteBuffer.wrap(compressCertificate);
                int length = buffer.get() & 0xff;
                convertUInt16ArrayToJa3(buffer, 1, length + 1, list);
            }
            appendPeerPrintIntegers(peetPrint, list, false);
        }
        appendPeerPrintIntegers(peetPrint, clientHello.getCipherSuites(), false);
        List<Integer> extensionTypes = new ArrayList<>(clientHello.getExtensionTypes().keySet());
        appendPeerPrintIntegers(peetPrint, extensionTypes, true);
        peetPrint.deleteCharAt(peetPrint.length() - 1);
        return peetPrint.toString();
    }

    private void appendPeerPrintIntegers(StringBuilder peetPrint, List<Integer> values, boolean sort) {
        List<String> list = new ArrayList<>(values.size());
        for(Integer v : values) {
            if (isNotGrease(v)) {
                list.add(String.valueOf(v));
            } else {
                list.add(GREASE_TEXT);
            }
        }
        if (sort) {
            Collections.sort(list);
        }
        peetPrint.append(String.join("-", list)).append("|");
    }

    private List<String> createApplicationLayerProtocols() {
        List<String> applicationLayerProtocols = clientHello.getApplicationLayerProtocols();
        List<String> list = new ArrayList<>(3);
        for (String applicationLayerProtocol : applicationLayerProtocols) {
            switch (applicationLayerProtocol) {
                case "http/0.9":
                    list.add("0.9");
                    break;
                case "http/1.0":
                    list.add("1.0");
                    break;
                case "http/1.1":
                    list.add("1.1");
                    break;
                case "h2":
                    list.add("2");
                    break;
                case "h3":
                case "h3-27":
                case "h3-29":
                    list.add("3");
                    break;
                case "dot":
                case "apns-security-v3":
                case "apns-pack-v1":
                case "spdy/3.1":
                case "hq-interop":
                    break;
                default:
                    log.warn("createApplicationLayerProtocols unknown application layer protocol: {}", applicationLayerProtocol);
                    break;
            }
        }
        return list;
    }

    private List<String> createSupportedProtocols() {
        List<String> applicationLayerProtocols = clientHello.getApplicationLayerProtocols();
        List<String> list = new ArrayList<>(3);
        for (String applicationLayerProtocol : applicationLayerProtocols) {
            switch (applicationLayerProtocol) {
                case "http/0.9":
                    list.add("http09");
                    break;
                case "http/1.0":
                    list.add("http10");
                    break;
                case "http/1.1":
                    list.add("http11");
                    break;
                case "h2":
                    list.add(Vpn.HTTP2_PROTOCOL);
                    break;
                case "h3":
                case "h3-27":
                case "h3-29":
                    list.add("h3");
                    break;
                case "dot":
                case "apns-security-v3":
                case "apns-pack-v1":
                case "spdy/3.1":
                case "hq-interop":
                    break;
                default:
                    log.warn("createSupportedProtocols unknown application layer protocol: {}", applicationLayerProtocol);
                    break;
            }
        }
        return list;
    }

    /**
     * version:772|
     * ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|
     * ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281-GREASE|
     * groups:GREASE-25497-29-23-24|
     * points:0|
     * compression:0|
     * supported_versions:GREASE-772-771|
     * supported_protocols:h2-http11|
     * key_shares:GREASE-25497-29|
     * psk:1|
     * signature_algs:1027-2052-1025-1283-2053-1281-2054-1537|
     * early_data:0|
     */
    @Override
    public String getScrapflyFP() {
        Map<Integer, byte[]> extensionTypes = new LinkedHashMap<>(clientHello.getExtensionTypes());
        StringBuilder builder = new StringBuilder();
        builder.append("version:").append(getVersion(extensionTypes)).append("|");
        {
            List<String> list = buildIntegerList(clientHello.getCipherSuites());
            builder.append("ch_ciphers:").append(String.join("-", list)).append("|");
        }
        {
            List<Integer> extensions = new ArrayList<>(extensionTypes.size());
            Map<Integer, Integer> map = new LinkedHashMap<>();
            for(Integer extensionType : extensionTypes.keySet()) {
                if (extensionType == TlsConstants.ExtensionType.padding.value) {
                    continue;
                }
                if (isNotGrease(extensionType)) {
                    extensions.add(extensionType);
                } else {
                    map.put(extensions.size() + map.size(), extensionType);
                }
            }
            Collections.sort(extensions);
            for (Map.Entry<Integer, Integer> entry : map.entrySet()) {
                extensions.add(entry.getKey(), entry.getValue());
            }
            List<String> list = buildIntegerList(extensions);
            builder.append("ch_extensions:").append(String.join("-", list)).append("|");
        }
        {
            List<String> list = buildIntegerList(clientHello.getEllipticCurves());
            builder.append("groups:").append(String.join("-", list)).append("|");
        }
        {
            List<String> list = buildIntegerList(clientHello.getEllipticCurvePointFormats());
            builder.append("points:").append(String.join("-", list)).append("|");
        }
        {
            List<String> list = buildIntegerList(clientHello.getCompressionMethods());
            builder.append("compression:").append(String.join("-", list)).append("|");
        }
        byte[] supportedVersions = extensionTypes.get(TlsConstants.ExtensionType.supported_versions.value & 0xffff);
        if(supportedVersions != null) {
            ByteBuffer buffer = ByteBuffer.wrap(supportedVersions);
            int length = buffer.get() & 0xff;
            List<Integer> versions = new ArrayList<>(length / 2);
            convertUInt16ArrayToJa3(buffer, 1, length + 1, versions);
            List<String> list = buildIntegerList(versions);
            builder.append("supported_versions:").append(String.join("-", list)).append("|");
        }
        {
            List<String> list = createSupportedProtocols();
            builder.append("supported_protocols:").append(String.join("-", list)).append("|");
        }
        byte[] keyShare = extensionTypes.get(TlsConstants.ExtensionType.key_share.value & 0xffff);
        if (keyShare != null) {
            ByteBuffer buffer = ByteBuffer.wrap(keyShare);
            int length = buffer.getShort() & 0xffff;
            if (length != (keyShare.length - 2)) {
                throw new IllegalStateException("Invalid keyShare");
            }
            List<Integer> list = new ArrayList<>(2);
            while (buffer.hasRemaining()) {
                int namedGroup = buffer.getShort() & 0xffff;
                int len = buffer.getShort() & 0xffff;
                if (len < 1) {
                    throw new IllegalStateException("Invalid keyShare");
                }
                buffer.position(buffer.position() + len);
                list.add(namedGroup);
            }
            builder.append("key_shares:").append(String.join("-", buildIntegerList(list))).append("|");
        }
        {
            builder.append("psk:1|");
        }
        {
            List<String> list = buildIntegerList(clientHello.getSignatureAlgorithms());
            builder.append("signature_algs:").append(String.join("-", list)).append("|");
        }
        {
            boolean isEarlyData = extensionTypes.containsKey(TlsConstants.ExtensionType.early_data.value & 0xffff);
            builder.append("early_data:").append(isEarlyData ? 1 : 0).append("|");
        }
        return builder.toString();
    }

    private static List<String> buildIntegerList(Collection<Integer> values) {
        List<String> list = new ArrayList<>(values.size());
        for(Integer value : values) {
            if(isNotGrease(value)) {
                list.add(String.valueOf(value));
            } else {
                list.add(GREASE_TEXT);
            }
        }
        return list;
    }

    private int getVersion(Map<Integer, byte[]> extensionTypes) {
        int version;
        byte[] supportedVersions = extensionTypes.get(TlsConstants.ExtensionType.supported_versions.value & 0xffff);
        if(supportedVersions != null) {
            ByteBuffer buffer = ByteBuffer.wrap(supportedVersions);
            int length = buffer.get() & 0xff;
            List<Integer> list = new ArrayList<>(length / 2);
            convertUInt16ArrayToJa3(buffer, 1, length + 1, list);
            version = 0;
            for (Integer v : list) {
                if (isNotGrease(v) && v > version) {
                    version = v;
                }
            }
        } else {
            version = clientHello.getClientVersion();
        }
        return version;
    }

    @Override
    public String getJa4Text() {
        Map<Integer, byte[]> extensionTypes = createExtensionTypesWithoutGrease();
        List<Integer> cipherSuites = createCipherSuitesWithoutGrease();
        StringBuilder ja4 = new StringBuilder();
        ja4.append(clientHello.getJa4Prefix());
        {
            int version = getVersion(extensionTypes);
            switch (version) {
                case 0x0304:
                    ja4.append("13");
                    break;
                case 0x0303:
                    ja4.append("12");
                    break;
                case 0x0302:
                    ja4.append("11");
                    break;
                case 0x0301:
                    ja4.append("10");
                    break;
                default:
                    log.warn("Unsupported version=0x{}", Integer.toHexString(version));
                    break;
            }
        }
        String hostName = clientHello.getHostName();
        if (hostName == null) {
            ja4.append("i");
        } else {
            ja4.append("d");
        }
        ja4.append(String.format("%02d", Math.min(99, cipherSuites.size())));
        ja4.append(String.format("%02d", Math.min(99, extensionTypes.size())));
        List<String> applicationLayerProtocols = clientHello.getApplicationLayerProtocols();
        if (applicationLayerProtocols.isEmpty()) {
            ja4.append("00");
        } else {
            String applicationLayerProtocol = applicationLayerProtocols.get(0);
            ja4.append(applicationLayerProtocol.charAt(0)).append(applicationLayerProtocol.charAt(applicationLayerProtocol.length() - 1));
        }
        {
            ja4.append("_");
            List<String> list = new ArrayList<>(cipherSuites.size());
            for(Integer cipherSuite : cipherSuites) {
                list.add(String.format("%04x", cipherSuite));
            }
            Collections.sort(list);
            ja4.append(DigestUtil.sha256Hex(String.join(",", list)), 0, 12);
        }
        {
            ja4.append("_");
            List<String> list = new ArrayList<>(extensionTypes.size());
            for(Integer extensionType : extensionTypes.keySet()) {
                if(extensionType == 0 || extensionType == 0x10) {
                    continue;
                }
                list.add(String.format("%04x", extensionType));
            }
            Collections.sort(list);
            StringBuilder content = new StringBuilder(String.join(",", list));
            List<Integer> signatureAlgorithms = clientHello.getSignatureAlgorithms();
            if (!signatureAlgorithms.isEmpty()) {
                content.append("_");
                list.clear();
                for(Integer signatureAlgorithm : signatureAlgorithms) {
                    list.add(String.format("%04x", signatureAlgorithm));
                }
                content.append(String.join(",", list));
            }
            log.debug("signatureAlgorithms={}", content);
            ja4.append(DigestUtil.sha256Hex(content.toString()), 0, 12);
        }
        return ja4.toString();
    }

    private void appendIntegers(List<Integer> list, StringBuilder builder, boolean filterGrease) {
        if (filterGrease) {
            List<Integer> copy = new ArrayList<>(list);
            for(Integer grease : GREASE) {
                copy.remove(grease);
            }
            list = copy;
        }
        if (!list.isEmpty()) {
            int first = list.get(0);
            builder.append(first);
            for (int i = 1; i < list.size(); i++) {
                builder.append("-").append(list.get(i));
            }
        }
    }

    @Override
    public String getJa3Text() {
        final StringBuilder ja3 = new StringBuilder();
        ja3.append(clientHello.getClientVersion());
        ja3.append(',');

        appendIntegers(clientHello.getCipherSuites(), ja3, true);
        ja3.append(',');

        appendIntegers(new ArrayList<>(clientHello.getExtensionTypes().keySet()), ja3, true);
        ja3.append(',');

        appendIntegers(clientHello.getEllipticCurves(), ja3, true);
        ja3.append(',');

        appendIntegers(clientHello.getEllipticCurvePointFormats(), ja3, false);
        return ja3.toString();
    }

    @Override
    public String getJa3nText() {
        final StringBuilder ja3 = new StringBuilder();
        ja3.append(clientHello.getClientVersion());
        ja3.append(',');

        appendIntegers(clientHello.getCipherSuites(), ja3, true);
        ja3.append(',');

        List<Integer> list = new ArrayList<>(clientHello.getExtensionTypes().keySet());
        Collections.sort(list);
        appendIntegers(list, ja3, true);
        ja3.append(',');

        appendIntegers(clientHello.getEllipticCurves(), ja3, true);
        ja3.append(',');

        appendIntegers(clientHello.getEllipticCurvePointFormats(), ja3, false);
        return ja3.toString();
    }

    /**
     * Parse TLS extensions from given TLS ClientHello packet.
     *
     * @param packet clienthello packet
     * @param off offset to start reading extensions
     * @param packetEnd offset where packet ends
     * @param ec string builder to output the generated ja3 string for elliptic curves
     * @param ecpf string builder to output the generated ja3 string for elliptic curve points
     */
    private static Map<Integer, byte[]> parseExtensions(final ByteBuffer packet, final int off, final int packetEnd, final List<Integer> ec,
                                                 final List<Integer> ecpf, List<Integer> signatureAlgorithms) {
        int offset = off;
        Map<Integer, byte[]> extensionTypes = new LinkedHashMap<>();
        while (offset < packetEnd) {
            int extensionType = getUInt16(packet, offset, packetEnd);
            offset += UINT16_LENGTH;
            int extensionLength = getUInt16(packet, offset, packetEnd);
            offset += UINT16_LENGTH;

            if (extensionType == TlsConstants.ExtensionType.supported_groups.value) {
                // Elliptic curve points
                int curveListLength = getUInt16(packet, offset, packetEnd);
                convertUInt16ArrayToJa3(packet, offset + UINT16_LENGTH, offset + UINT16_LENGTH + curveListLength, ec);
            } else if (extensionType == TYPE_ELLIPTIC_CURVE_POINT_FORMATS) {
                // Elliptic curve point formats
                int curveFormatLength = packet.get(offset) & BITMASK;
                convertUInt8ArrayToJa3(packet, offset + 1, offset + 1 + curveFormatLength, ecpf);
            } else if (extensionType == TlsConstants.ExtensionType.signature_algorithms.value) {
                int signatureAlgorithmsLength = getUInt16(packet, offset, packetEnd);
                convertUInt16ArrayToJa3(packet, offset + UINT16_LENGTH, offset + UINT16_LENGTH + signatureAlgorithmsLength, signatureAlgorithms);
            }

            byte[] data = new byte[extensionLength];
            for (int i = 0; i < extensionLength; i++) {
                data[i] = packet.get(offset + i);
            }
            extensionTypes.put(extensionType, data);

            offset += extensionLength;
        }
        return extensionTypes;
    }

    /**
     * Check if TLS protocols cipher, extension, named groups, signature algorithms and version values match GREASE values. <blockquote
     * cite="https://tools.ietf.org/html/draft-ietf-tls-grease"> GREASE (Generate Random Extensions And Sustain Extensibility), a mechanism to prevent
     * extensibility failures in the TLS ecosystem. It reserves a set of TLS protocol values that may be advertised to ensure peers correctly handle
     * unknown values </blockquote>
     *
     * @param value value to be checked against GREASE values
     * @return false if value matches GREASE value, true otherwise
     * @see <a href="https://tools.ietf.org/html/draft-ietf-tls-grease">draft-ietf-tls-grease</a>
     */
    private static boolean isNotGrease(final int value) {
        for (int j : GREASE) {
            if (value == j) {
                return false;
            }
        }
        return true;
    }

    /**
     * Convert unsigned 16-bit integer array to JA3 string.
     * <p>
     * Note: This method does not check alignment of the start and end are 2-bytes. The caller is responsible for ensuring a valid 16-bit integer
     * array is provided.
     *
     * @param source packet source
     * @param start start offset of array in packet
     * @param end end offset of array in packet
     * @param out string builder to output the generated JA3 string
     * @throws BufferUnderflowException when source packet does not have enough bytes to read
     */
    private static void convertUInt16ArrayToJa3(final ByteBuffer source, final int start, final int end, final List<Integer> out) {
        int st = start;
        for (; st < end; st += UINT16_LENGTH) {
            int value = getUInt16(source, st, end);
            out.add(value);
        }
    }

    /**
     * Convert unsigned 8-bit integer array to JA3 string.
     *
     * @param source packet source
     * @param start start offset of array in packet
     * @param end end offset of array in packet
     * @param out string builder to output the generated JA3 string
     * @throws BufferUnderflowException when source packet does not have enough bytes to read
     */
    static void convertUInt8ArrayToJa3(final ByteBuffer source, final int start, final int end, final List<Integer> out) {
        int st = start;
        for (; st < end; st++) {
            out.add(getByte(source, st, end) & 0xff);
        }
    }

    /**
     * Read unsigned 24-bit integer from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return 24-bit integer from network
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static int getUInt24(final ByteBuffer source, final int start, final int end) {
        if (start + UINT24_LENGTH > end) {
            throw new BufferUnderflowException();
        }

        return ((source.get(start) & BITMASK) << TWO_BYTES)
                + ((source.get(start + 1) & BITMASK) << ONE_BYTE) + (source.get(start + 2) & BITMASK);
    }

    /**
     * Read unsigned 16-bit integer from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return unsigned integer
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static int getUInt16(final ByteBuffer source, final int start, final int end) {
        if (start + UINT16_LENGTH > end) {
            throw new BufferUnderflowException();
        }

        return ((source.get(start) & BITMASK) << ONE_BYTE) + (source.get(start + 1) & BITMASK);
    }

    /**
     * Read a single byte from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return a byte
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static byte getByte(final ByteBuffer source, final int start, final int end) {
        if (start + 1 > end) {
            throw new BufferUnderflowException();
        }

        return source.get(start);
    }
}
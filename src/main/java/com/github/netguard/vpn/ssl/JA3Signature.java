/**
 *  Copyright 2019, Oath Inc.
 *  Licensed under the terms of the Apache 2.0 license.
 *  See LICENSE file in {@link https://github.com/lafaspot/ja3_4java/blob/master/LICENSE} for terms.
 */
package com.github.netguard.vpn.ssl;

import cn.hutool.crypto.digest.DigestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates JA3 signature based on the implementation described at <a href="https://github.com/salesforce/ja3">ja3</a>.
 *
 */
public final class JA3Signature {

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
     * Newline character.
     */
    private static final byte NEWLINE = 0x0a;

    /**
     * Vertical Tab character.
     */
    private static final byte VERTICALTAB = 0x0b;

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

            off += packet.get(off) + SSL_VERSION_LENGTH; // Skip Compression Methods and length of extensions

            final List<Integer> ec = new ArrayList<>(); // elliptic curves
            final List<Integer> ecpf = new ArrayList<>(); // elliptic curve point formats
            final List<Integer> signatureAlgorithms = new ArrayList<>();
            Map<Integer, byte[]> extensionTypes = parseExtensions(packet, off, end, ec, ecpf, signatureAlgorithms);
            return new JA3Signature(clientVersion, cipherSuites, extensionTypes, ec, ecpf, signatureAlgorithms,
                    hostName, applicationLayerProtocols);
        } catch (BufferUnderflowException | ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    private final int clientVersion;
    private final List<Integer> cipherSuites;
    private final Map<Integer, byte[]> extensionTypes;
    private final List<Integer> ec;
    private final List<Integer> ecpf;
    private final List<Integer> signatureAlgorithms;
    private final String hostName;
    private final List<String> applicationLayerProtocols;

    private JA3Signature(int clientVersion, List<Integer> cipherSuites, Map<Integer, byte[]> extensionTypes,
                         List<Integer> ec, List<Integer> ecpf, List<Integer> signatureAlgorithms,
                         String hostName, List<String> applicationLayerProtocols) {
        this.clientVersion = clientVersion;
        this.cipherSuites = Collections.unmodifiableList(cipherSuites);
        this.extensionTypes = Collections.unmodifiableMap(extensionTypes);
        this.ec = Collections.unmodifiableList(ec);
        this.ecpf = Collections.unmodifiableList(ecpf);
        this.signatureAlgorithms = Collections.unmodifiableList(signatureAlgorithms);
        this.hostName = hostName;
        this.applicationLayerProtocols = Collections.unmodifiableList(applicationLayerProtocols);
    }

    public String getJa4Text() {
        StringBuilder ja4 = new StringBuilder();
        ja4.append("t");
        {
            int version;
            final int SUPPORTED_VERSIONS = 0x2b;
            byte[] supportedVersions = extensionTypes.get(SUPPORTED_VERSIONS);
            if(supportedVersions != null && supportedVersions.length >= 3) {
                version = 0;
                ByteBuffer buffer = ByteBuffer.wrap(supportedVersions);
                int length = buffer.get() & 0xff;
                for (int i = 0; i < length; i += 2) {
                    int v = buffer.getShort() & 0xffff;
                    if (isNotGrease(v)) {
                        if (v > version) {
                            version = v;
                        }
                    }
                }
            } else {
                version = clientVersion;
            }
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
                default:
                    throw new IllegalStateException("version=0x" + Integer.toHexString(version));
            }
        }
        if (hostName == null) {
            ja4.append("i");
        } else {
            ja4.append("d");
        }
        ja4.append(String.format("%02d", Math.min(99, cipherSuites.size())));
        ja4.append(String.format("%02d", Math.min(99, extensionTypes.size())));
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

    private void appendIntegers(List<Integer> list, StringBuilder builder) {
        if (!list.isEmpty()) {
            int first = list.get(0);
            builder.append(first);
            for (int i = 1; i < list.size(); i++) {
                builder.append("-").append(list.get(i));
            }
        }
    }

    public String getJa3Text() {
        final StringBuilder ja3 = new StringBuilder();
        ja3.append(clientVersion);
        ja3.append(',');

        appendIntegers(cipherSuites, ja3);
        ja3.append(',');

        appendIntegers(new ArrayList<>(extensionTypes.keySet()), ja3);
        ja3.append(',');

        appendIntegers(ec, ja3);
        ja3.append(',');

        appendIntegers(ecpf, ja3);
        return ja3.toString();
    }

    public String getJa3nText() {
        final StringBuilder ja3 = new StringBuilder();
        ja3.append(clientVersion);
        ja3.append(',');

        appendIntegers(cipherSuites, ja3);
        ja3.append(',');

        List<Integer> list = new ArrayList<>(extensionTypes.keySet());
        Collections.sort(list);
        appendIntegers(list, ja3);
        ja3.append(',');

        appendIntegers(ec, ja3);
        ja3.append(',');

        appendIntegers(ecpf, ja3);
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

            if (extensionType == NEWLINE) {
                // Elliptic curve points
                int curveListLength = getUInt16(packet, offset, packetEnd);
                convertUInt16ArrayToJa3(packet, offset + UINT16_LENGTH, offset + UINT16_LENGTH + curveListLength, ec);
            } else if (extensionType == VERTICALTAB) {
                // Elliptic curve point formats
                int curveFormatLength = packet.get(offset) & BITMASK;
                convertUInt8ArrayToJa3(packet, offset + 1, offset + 1 + curveFormatLength, ecpf);
            } else if (extensionType == 0xd) {
                int signatureAlgorithmsLength = getUInt16(packet, offset, packetEnd);
                convertUInt16ArrayToJa3(packet, offset + UINT16_LENGTH, offset + UINT16_LENGTH + signatureAlgorithmsLength, signatureAlgorithms);
            }

            if (isNotGrease(extensionType)) {
                byte[] data = new byte[extensionLength];
                for (int i = 0; i < extensionLength; i++) {
                    data[i] = packet.get(offset + i);
                }
                extensionTypes.put(extensionType, data);
            }

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
            if (isNotGrease(value)) {
                out.add(value);
            }
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
    private static void convertUInt8ArrayToJa3(final ByteBuffer source, final int start, final int end, final List<Integer> out) {
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
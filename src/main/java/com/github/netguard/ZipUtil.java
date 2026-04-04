package com.github.netguard;

import org.apache.commons.io.IOUtils;
import org.brotli.dec.BrotliInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class ZipUtil {

    private static final Logger log = LoggerFactory.getLogger(ZipUtil.class);

    public static byte[] unDeflate(byte[] data) throws IOException {
        return IOUtils.toByteArray(new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(true)));
    }

    public static byte[] zlib(byte[] data) throws IOException {
        return zlib(data, Deflater.DEFAULT_COMPRESSION);
    }

    public static byte[] zlib(byte[] data, int level) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflater = new DeflaterOutputStream(out, new Deflater(level))) {
            deflater.write(data);
        }
        return out.toByteArray();
    }

    public static byte[] unZlib(byte[] data) throws IOException {
        return IOUtils.toByteArray(new InflaterInputStream(new ByteArrayInputStream(data)));
    }

    public static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }

    public static byte[] unGzip(byte[] data) throws IOException {
        return IOUtils.toByteArray(new GZIPInputStream(new ByteArrayInputStream(data)));
    }

    public static byte[] unBrotli(byte[] data) throws IOException {
        try (InputStream inputStream = new BrotliInputStream(new ByteArrayInputStream(data))) {
            return IOUtils.toByteArray(inputStream);
        }
    }

    /**
     * Decompress the given data according to the specified content encoding.
     *
     * @param contentEncoding the value of the {@code Content-Encoding} header (e.g. "gzip", "deflate", "br"),
     *                        or {@code null} if no encoding was applied
     * @param data            the compressed byte array
     * @return the decompressed byte array, or the original {@code data} if decompression fails
     * @throws UnsupportedOperationException if {@code contentEncoding} is not {@code null} and is not a
     *                                       supported encoding
     */
    public static byte[] decodeContent(String contentEncoding, byte[] data) {
        if (contentEncoding == null) {
            return data;
        }
        try {
            switch (contentEncoding) {
                case "deflate":
                    return unDeflate(data);
                case "gzip":
                    return unGzip(data);
                case "br":
                    return unBrotli(data);
                default:
                    throw new UnsupportedOperationException("contentEncoding=" + contentEncoding);
            }
        } catch (IOException e) {
            log.debug("decodeContent failed: contentEncoding={}", contentEncoding, e);
            return data;
        }
    }

    private ZipUtil() {
    }
}

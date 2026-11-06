package com.github.netguard.vpn.tcp;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/**
 * {@link ClientHelloRecord#readMorePrologue} must keep every byte it takes from the stream, because the
 * connection is forwarded from the prologue.
 */
public class ClientHelloRecordTest extends TestCase {

    private static ClientHelloRecord record(String prologue) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(prologue.getBytes(StandardCharsets.US_ASCII));
        return ClientHelloRecord.prologue(baos, new DataInputStream(new ByteArrayInputStream(new byte[0])));
    }

    /** Serves the given bytes, then behaves like a socket whose read timeout expired. */
    private static DataInputStream thenTimeout(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.US_ASCII);
        return new DataInputStream(new InputStream() {
            private int pos;

            @Override
            public int read() throws IOException {
                if (pos < bytes.length) {
                    return bytes[pos++] & 0xff;
                }
                throw new SocketTimeoutException("Read timed out");
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (pos < bytes.length) {
                    int count = Math.min(len, bytes.length - pos);
                    System.arraycopy(bytes, pos, b, off, count);
                    pos += count;
                    return count;
                }
                throw new SocketTimeoutException("Read timed out");
            }
        });
    }

    private static DataInputStream thenEof(String data) {
        return new DataInputStream(new ByteArrayInputStream(data.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String prologue(ClientHelloRecord record) {
        return new String(record.prologue, StandardCharsets.US_ASCII);
    }

    public void testReadsRequestedBytes() throws IOException {
        assertEquals("XYZW", prologue(record("XY").readMorePrologue(thenEof("ZWV"), 4)));
    }

    public void testTimeoutKeepsBytesThatArrived() throws IOException {
        assertEquals("XYZ", prologue(record("XY").readMorePrologue(thenTimeout("Z"), 5)));
    }

    public void testTimeoutWithNothingReturnsSameRecord() throws IOException {
        ClientHelloRecord record = record("XY");
        assertSame(record, record.readMorePrologue(thenTimeout(""), 5));
    }

    public void testCloseKeepsBytesThatArrived() throws IOException {
        assertEquals("XYZ", prologue(record("XY").readMorePrologue(thenEof("Z"), 5)));
    }

    public void testCloseWithNothingThrows() throws IOException {
        try {
            record("XY").readMorePrologue(thenEof(""), 5);
            fail("EOFException expected");
        } catch (EOFException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("prologueLength=2, needPrologueCount=5"));
        }
    }
}

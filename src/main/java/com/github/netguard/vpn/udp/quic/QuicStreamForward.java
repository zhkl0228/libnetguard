package com.github.netguard.vpn.udp.quic;

import com.github.netguard.Inspector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class QuicStreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(QuicStreamForward.class);

    public interface QuicStream {

        int getStreamId();
        InputStream openInputStream() throws IOException;
        OutputStream openOutputStream() throws IOException;
        void resetStream(int applicationProtocolErrorCode);

    }

    final boolean server;
    final boolean bidirectional;
    final QuicStream from;
    final QuicStream to;

    public QuicStreamForward(boolean server, boolean bidirectional, QuicStream from, QuicStream to) {
        this.server = server;
        this.bidirectional = bidirectional;
        this.from = from;
        this.to = to;
    }

    void doForward(byte[] buf, int read, DataOutputStream outputStream) throws IOException {
        outputStream.write(buf, 0, read);
    }

    @Override
    public void run() {
        try (InputStream inputStream = from.openInputStream();
             OutputStream outputStream = to.openOutputStream();
             DataOutputStream dataOutput = new DataOutputStream(outputStream)) {
            byte[] buf = new byte[2048];
            while (true) {
                try {
                    int read = inputStream.read(buf);
                    log.debug("{} read {} bytes bidirectional={} from {} to {}", server ? "Server" : "Client", read, bidirectional, from, to);
                    if (read == -1) {
                        throw new EOFException();
                    }
                    if (read > 0) {
                        if (log.isDebugEnabled()) {
                            log.debug("{}", Inspector.inspectString(Arrays.copyOf(buf, read), (server ? "Server" : "Client") + " forward from=" + from + ", to=" + to));
                        }
                        doForward(buf, read, dataOutput);
                        outputStream.flush();
                    }
                } catch (IOException e) {
                    onEOF(dataOutput);
                    log.trace("forward from={}, to={}", from, to, e);
                    break;
                }
            }
        } catch (IOException e) {
            log.debug("forward stream from={}, to={}", from, to, e);
        } catch (Exception e) {
            log.warn("forward stream from={}, to={}", from, to, e);
        }
        log.debug("{} exiting {}", server ? "Server" : "Client", getClass().getSimpleName());
    }

    void onEOF(DataOutputStream outputStream) throws IOException {
    }

}

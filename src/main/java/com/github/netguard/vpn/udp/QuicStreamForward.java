package com.github.netguard.vpn.udp;

import com.github.netguard.Inspector;
import net.luminis.quic.QuicStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;

class QuicStreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(QuicStreamForward.class);

    static void forward(QuicStream clientStream, QuicStream serverStream, boolean bidirectional, ExecutorService executorService, boolean filterHttp3) {
        if (filterHttp3) {
            executorService.submit(new Http3StreamForward(true, bidirectional, serverStream, clientStream));
            if (bidirectional) {
                executorService.submit(new Http3StreamForward(false, true, clientStream, serverStream));
            }
        } else {
            executorService.submit(new QuicStreamForward(true, bidirectional, serverStream, clientStream));
            if (bidirectional) {
                executorService.submit(new QuicStreamForward(false, true, clientStream, serverStream));
            }
        }
    }

    final boolean server;
    private final boolean bidirectional;
    final QuicStream from, to;

    QuicStreamForward(boolean server, boolean bidirectional, QuicStream from, QuicStream to) {
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
        try (InputStream inputStream = from.getInputStream(); DataOutputStream outputStream = new DataOutputStream(to.getOutputStream())) {
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
                        doForward(buf, read, outputStream);
                        outputStream.flush();
                    }
                } catch (IOException e) {
                    log.trace("forward from={}, to={}", from, to, e);
                    break;
                }
            }
        } catch (Exception e) {
            log.warn("open stream from={}, to={}", from, to, e);
        }
    }

}

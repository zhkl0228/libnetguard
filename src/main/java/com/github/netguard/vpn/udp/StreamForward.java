package com.github.netguard.vpn.udp;

import com.github.netguard.Inspector;
import net.luminis.quic.QuicStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

class StreamForward implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(StreamForward.class);

    static void forward(QuicStream clientStream, QuicStream serverStream, boolean bidirectional) {
        Thread s2c = new Thread(new StreamForward(true, bidirectional, serverStream, clientStream), "forward from=" + serverStream + ", to=" + clientStream);
        s2c.setDaemon(true);
        s2c.start();
        if (bidirectional) {
            Thread c2s = new Thread(new StreamForward(false, true, clientStream, serverStream), "forward from=" + clientStream + ", to=" + serverStream);
            c2s.setDaemon(true);
            c2s.start();
        }
    }

    private final boolean server;
    private final boolean bidirectional;
    private final QuicStream from, to;

    public StreamForward(boolean server, boolean bidirectional, QuicStream from, QuicStream to) {
        this.server = server;
        this.bidirectional = bidirectional;
        this.from = from;
        this.to = to;
    }

    @Override
    public void run() {
        try (InputStream inputStream = from.getInputStream(); OutputStream outputStream = to.getOutputStream()) {
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
                            log.debug("{}", Inspector.inspectString(Arrays.copyOf(buf, read), "forward from=" + from + ", to=" + to));
                        }
                        outputStream.write(buf, 0, read);
                        outputStream.flush();
                    }
                } catch (IOException e) {
                    log.trace("forward from={}, to={}", from, to, e);
                    break;
                }
            }
        } catch (IOException e) {
            log.warn("open stream from={}, to={}", from, to, e);
        }
    }
}

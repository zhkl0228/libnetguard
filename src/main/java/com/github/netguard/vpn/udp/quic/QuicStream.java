package com.github.netguard.vpn.udp.quic;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface QuicStream {

    int getStreamId();

    InputStream openInputStream() throws IOException;

    OutputStream openOutputStream() throws IOException;

    void resetStream(int applicationProtocolErrorCode);

}

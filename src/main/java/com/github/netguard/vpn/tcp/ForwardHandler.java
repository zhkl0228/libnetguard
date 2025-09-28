package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface ForwardHandler {

    void initialize() throws IOException;

    void handleClient(byte[] buf, InputStream clientInput, OutputStream serverOutput) throws IOException;

    void handleServer(byte[] buf, InputStream serverInput, OutputStream clientOutput) throws IOException;

}

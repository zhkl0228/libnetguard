package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface ForwardHandler {

    void handleClient(InputStream clientInput, OutputStream serverOutput) throws IOException;

    void handleServer(InputStream serverInput, OutputStream clientOutput) throws IOException;

}

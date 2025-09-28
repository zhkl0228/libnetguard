package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface ForwardHandler {

    void handleClient(byte[] buf, InputStream inputStream, OutputStream outputStream) throws IOException;

    void handleServer(byte[] buf, InputStream inputStream, OutputStream outputStream) throws IOException;

}

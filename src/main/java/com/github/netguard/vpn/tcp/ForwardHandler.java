package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public interface ForwardHandler {

    void handleClient(Socket socket, byte[] buf, InputStream inputStream, OutputStream outputStream) throws IOException;

    void handleServer(Socket socket, byte[] buf, InputStream inputStream, OutputStream outputStream) throws IOException;

}

package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public interface ForwardHandler {

    default void initContext(ForwardContext context) {
    }

    void handleClient(Socket clientSocket, byte[] buf, InputStream clientInputStream, OutputStream serverOutputStream) throws IOException;

    void handleServer(Socket serverSocket, byte[] buf, InputStream serverInputStream, OutputStream clientOutputStream) throws IOException;

}

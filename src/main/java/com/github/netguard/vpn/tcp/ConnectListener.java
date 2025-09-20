package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.net.Socket;

public interface ConnectListener {

    void onConnected(Socket socket) throws IOException;

}

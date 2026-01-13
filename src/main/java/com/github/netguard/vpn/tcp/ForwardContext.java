package com.github.netguard.vpn.tcp;

import java.net.Socket;

public interface ForwardContext {

    Socket getClinetSocket();
    Socket getServerSocket();

}

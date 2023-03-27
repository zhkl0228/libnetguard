package tech.httptoolkit.android.vpn;

import java.net.SocketAddress;

public interface Mitm {

    SocketAddress mitm(String ip, int port);

}

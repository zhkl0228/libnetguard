package eu.faircode.netguard;

import com.github.netguard.vpn.Vpn;

public interface ConnectionListener {

    void notifyConnected(Vpn vpn, Connected connected);

    void notifyDisconnected(Vpn vpn, Connected connected);

    void notifyVpnStop(Vpn vpn);

}

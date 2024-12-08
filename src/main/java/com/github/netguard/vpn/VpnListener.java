package com.github.netguard.vpn;

import com.github.netguard.handler.replay.Replay;

public interface VpnListener {

    default void initializeReplay(Replay replay) {
        throw new UnsupportedOperationException("Not implemented yet: Please extends com.github.netguard.vpn.BaseVpnListener");
    }

    void onConnectClient(Vpn vpn);

}

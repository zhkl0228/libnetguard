package com.github.netguard.vpn;

import com.github.netguard.handler.replay.Replay;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseVpnListener implements VpnListener {

    private static final Logger log = LoggerFactory.getLogger(BaseVpnListener.class);

    private final IPacketCapture packetCapture;

    public BaseVpnListener() {
        this.packetCapture = createPacketCapture();
    }

    protected abstract IPacketCapture createPacketCapture();

    @Override
    public void initializeReplay(Replay replay) {
        if (packetCapture != null) {
            packetCapture.replay(replay);
        }
    }

    @Override
    public final void onConnectClient(Vpn vpn) {
        log.info("vpn client connected: {}, impl={}", vpn.getClientOS(), vpn.getClass().getSimpleName());
        if (packetCapture != null) {
            vpn.setPacketCapture(packetCapture);
        }
    }

}

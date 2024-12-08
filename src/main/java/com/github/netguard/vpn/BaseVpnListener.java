package com.github.netguard.vpn;

import com.github.netguard.handler.replay.Replay;

public abstract class BaseVpnListener implements VpnListener {

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
        System.out.println("client: " + vpn.getClientOS() + ", impl=" + vpn.getClass());
        if (packetCapture != null) {
            vpn.setPacketCapture(packetCapture);
        }
    }

}

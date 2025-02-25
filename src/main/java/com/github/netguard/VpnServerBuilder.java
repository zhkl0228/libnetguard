package com.github.netguard;

import com.github.netguard.vpn.VpnListener;

import java.io.File;
import java.io.IOException;

public class VpnServerBuilder {

    public static VpnServerBuilder create() {
        return new VpnServerBuilder();
    }

    private VpnServerBuilder() {
    }

    private int port;

    public VpnServerBuilder withPort(int port) {
        this.port = port;
        return this;
    }

    private boolean preparePreMasterSecretsLogFile;

    public VpnServerBuilder preparePreMasterSecretsLogFile() {
        this.preparePreMasterSecretsLogFile = true;
        return this;
    }

    private int broadcastSeconds;

    public VpnServerBuilder enableBroadcast(int seconds) {
        this.broadcastSeconds = seconds;
        return this;
    }

    private int transparentProxyingPort = -1;

    public VpnServerBuilder enableTransparentProxying() {
        return enableTransparentProxying(0);
    }

    public VpnServerBuilder enableTransparentProxying(int port) {
        this.transparentProxyingPort = port;
        return this;
    }

    private boolean enableUdpRelay;

    public VpnServerBuilder enableUdpRelay() {
        this.enableUdpRelay = true;
        return this;
    }

    private File replayLogFile;

    public VpnServerBuilder withReplayLogFile(File replayLogFile) {
        this.replayLogFile = replayLogFile;
        return this;
    }

    private VpnListener vpnListener;

    public VpnServerBuilder withVpnListener(VpnListener vpnListener) {
        this.vpnListener = vpnListener;
        return this;
    }

    private boolean disableNetGuard;

    @SuppressWarnings("unused")
    public VpnServerBuilder disableNetGuard() {
        this.disableNetGuard = true;
        return this;
    }

    public VpnServer startServer() throws IOException {
        VpnServer server = port > 0 ? new VpnServer(port) : new VpnServer();
        if (preparePreMasterSecretsLogFile) {
            server.preparePreMasterSecretsLogFile();
        }
        if(broadcastSeconds > 0) {
            server.enableBroadcast(broadcastSeconds);
        }
        if (transparentProxyingPort == 0) {
            server.enableTransparentProxying();
        } else if(transparentProxyingPort > 0) {
            server.enableTransparentProxying(transparentProxyingPort);
        }
        if (enableUdpRelay) {
            server.enableUdpRelay();
        }
        if(replayLogFile != null) {
            server.setReplayLogFile(replayLogFile);
        }
        if (vpnListener != null) {
            server.setVpnListener(vpnListener);
        }
        if (disableNetGuard) {
            server.disableNetGuard();
        }
        server.start();
        return server;
    }

}

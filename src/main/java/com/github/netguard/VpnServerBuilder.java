package com.github.netguard;

import cn.hutool.core.io.FileUtil;
import com.github.netguard.vpn.VpnListener;
import name.neykov.secrets.AgentAttach;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;

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

    private File preparePreMasterSecretsLogFile;

    public VpnServerBuilder enablePreMasterSecretsLogFile() {
        File preMasterSecretsLogFile = new File("target/pre_master_secrets.log");
        return enablePreMasterSecretsLogFile(preMasterSecretsLogFile);
    }

    public VpnServerBuilder enablePreMasterSecretsLogFile(File preparePreMasterSecretsLogFile) {
        this.preparePreMasterSecretsLogFile = preparePreMasterSecretsLogFile;
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

    private boolean enableSocksProxy;

    public VpnServerBuilder enableSocksProxy() {
        this.enableSocksProxy = true;
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
        VpnServer server = createVpnServer();
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
        server.enableSocksProxy = enableSocksProxy;
        server.start();
        return server;
    }

    private VpnServer createVpnServer() throws IOException {
        VpnServer server = port > 0 ? new VpnServer(port) : new VpnServer();
        if (preparePreMasterSecretsLogFile != null) {
            preparePreMasterSecretsLogFile(preparePreMasterSecretsLogFile);
        }
        if(broadcastSeconds > 0) {
            server.enableBroadcast(broadcastSeconds);
        }
        if (transparentProxyingPort == 0) {
            server.enableTransparentProxying();
        } else if(transparentProxyingPort > 0) {
            server.enableTransparentProxying(transparentProxyingPort);
        }
        return server;
    }

    private void preparePreMasterSecretsLogFile(File preMasterSecretsLogFile) {
        String preMasterSecretsLogPath = preMasterSecretsLogFile.getAbsolutePath();
        FileUtil.del(preMasterSecretsLogFile);
        CodeSource codeSource = AgentAttach.class.getProtectionDomain().getCodeSource();
        if (codeSource != null) {
            try {
                URL jarUrl = codeSource.getLocation();
                File jarFile = new File(jarUrl.toURI());
                String name = ManagementFactory.getRuntimeMXBean().getName();
                String pid = name.split("@")[0];
                String jarPath = jarFile.getAbsolutePath();
                System.out.printf("VM option: -javaagent:%s=%s%n", jarPath, preMasterSecretsLogPath);
                System.out.printf("java -jar %s %s %s%n", jarPath.replace(FileUtil.getUserHomePath(), "~"),
                        pid,
                        preMasterSecretsLogPath.replace(FileUtil.getUserHomePath(), "~"));
            } catch (URISyntaxException e) {
                throw new IllegalStateException(e);
            }
        }
    }

}

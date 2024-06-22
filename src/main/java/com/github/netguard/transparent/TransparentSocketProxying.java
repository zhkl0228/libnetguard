package com.github.netguard.transparent;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.InspectorVpn;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import eu.faircode.netguard.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TransparentSocketProxying extends ProxyVpn implements InspectorVpn {

    private static final Logger log = LoggerFactory.getLogger(TransparentSocketProxying.class);

    private final Socket socket;

    public TransparentSocketProxying(List<ProxyVpn> clients, RootCert rootCert, Socket socket) {
        super(clients, rootCert);
        this.socket = socket;
    }

    @Override
    public boolean isTransparentProxying() {
        return true;
    }

    private static final Pattern PATTERN = Pattern.compile("127\\.0\\.0\\.1:(\\d+)\\s+<-\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)\\s+<-\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");

    @Override
    public void run() {
        try {
            Process process = Runtime.getRuntime().exec("sudo /sbin/pfctl -s state");
            int exitCode = process.waitFor();
            log.debug("exitCode={}, socket={}", exitCode, socket);
            if (exitCode != 0) {
                throw new IllegalStateException("exitCode=" + exitCode);
            }
            try (InputStream inputStream = process.getInputStream()) {
                String output = IoUtil.read(inputStream, StandardCharsets.UTF_8);
                log.trace("output={}", output);
                Matcher matcher = PATTERN.matcher(output);
                while (matcher.find()) {
                    int listenPort = Integer.parseInt(matcher.group(1));
                    String destAddr = matcher.group(2);
                    int destPort = Integer.parseInt(matcher.group(3));
                    String srcAddr = matcher.group(4);
                    int srcPort = Integer.parseInt(matcher.group(5));
                    log.trace("listenPort={}, destAddr={}, destPort={}, srcAddr={}, srcPort={}", listenPort, destAddr, destPort, srcAddr, srcPort);
                    InetSocketAddress socketAddress = getRemoteSocketAddress();
                    if (listenPort == socket.getLocalPort() && srcAddr.equals(socketAddress.getAddress().getHostAddress()) && srcPort == socketAddress.getPort()) {
                        Packet packet = new Packet();
                        packet.daddr = destAddr;
                        packet.dport = destPort;
                        SSLProxyV2.create(this, packet, 10000, socket);
                        return;
                    }
                }
                throw new EOFException("find dest failed: " + output + ", socket=" + socket);
            } finally {
                process.destroy();
            }
        } catch (Exception e) {
            log.warn("execute command failed.", e);
            IoUtil.close(socket);
        }
    }

    @Override
    protected void stop() {
        throw new UnsupportedOperationException();
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

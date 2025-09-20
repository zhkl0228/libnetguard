package com.github.netguard.proxy;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

public class HttpsProxyVpn extends ProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(HttpsProxyVpn.class);

    private final Socket socket;
    private final InputStream inputStream;

    public HttpsProxyVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, InputStream inputStream) {
        super(clients, rootCert);
        this.socket = socket;
        this.inputStream = inputStream;
    }

    @Override
    protected void doRunVpn() {
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(0x10)) {
            HttpRequest request = HttpProxyVpn.parseRequest(baos, inputStream, socket);
            if (request != null && request.method() == HttpMethod.CONNECT) {
                String uri = request.uri();
                int index = uri.lastIndexOf(":");
                if (index == -1) {
                    throw new IllegalStateException("Invalid uri: " + uri);
                }
                String host = uri.substring(0, index);
                int port = Integer.parseInt(uri.substring(index + 1));
                PrintWriter clientWriter = new PrintWriter(socket.getOutputStream());
                clientWriter.print(request.protocolVersion().toString());
                clientWriter.println(" 200 Connection Established\r");
                clientWriter.println("\r");
                clientWriter.flush();
                log.debug("doRunVpn connect host={}, port={}", host, port);
                Packet packet = new Packet();
                packet.daddr = host;
                packet.dport = port;
                SSLProxyV2.create(this, packet, 10000, socket, null);
                return;
            }
            throw new IOException("NOT support https proxy: request=" + request);
        } catch (Exception e) {
            log.warn("handle http proxy", e);
            IoUtil.close(socket);
        }
    }

    @Override
    protected void stop() {
        IoUtil.close(socket);
    }

    @Override
    public final ClientOS getClientOS() {
        return ClientOS.HttpsProxy;
    }

    @Override
    public InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

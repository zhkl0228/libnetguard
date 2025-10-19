package com.github.netguard.proxy;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.FallbackProxyVpn;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.SSLProxyV2;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.util.List;

public class HttpProxyVpn extends FallbackProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(HttpProxyVpn.class);

    private final PushbackInputStream inputStream;

    public HttpProxyVpn(Socket socket, List<ProxyVpn> clients, RootCert rootCert, PushbackInputStream inputStream) {
        super(socket, clients, rootCert);
        this.inputStream = inputStream;
    }

    @Override
    protected void doRunVpn() {
        try(final ByteArrayOutputStream baos = new ByteArrayOutputStream(0x10)) {
            HttpRequest request = parseRequest(baos, inputStream, socket);
            if (request != null) {
                inputStream.unread(baos.toByteArray());
                URL url = new URL(request.uri());
                String host = url.getHost();
                int port = url.getPort();
                if (port == -1) {
                    port = 80;
                }
                log.debug("doRunVpn connect host={}, port={}", host, port);
                Packet packet = new Packet();
                packet.daddr = host;
                packet.dport = port;
                SSLProxyV2.create(this, packet, 10000, socket, null, inputStream);
                return;
            }
            throw new IOException("NOT support http proxy");
        } catch (Exception e) {
            log.warn("handle http proxy", e);
            IoUtil.close(socket);
        }
    }

    static HttpRequest parseRequest(ByteArrayOutputStream baos, InputStream inputStream, Socket socket) throws IOException {
        DataInputStream dataInput = new DataInputStream(inputStream);
        DataOutput dataOutput = new DataOutputStream(baos);
        byte[] header = new byte[12];
        dataInput.readFully(header);
        dataOutput.write(header);
        HttpRequest request = ClientHelloRecord.detectHttp(baos, dataInput);
        log.debug("parseRequest socket={}, request={}", socket, request);
        return request;
    }

    @Override
    public final ClientOS getClientOS() {
        return ClientOS.HttpProxy;
    }

}

package com.github.netguard.sslvpn;

import cn.hutool.core.io.IoUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

public abstract class SSLVpn extends ProxyVpn {

    private static final ServerCertificate SSL_VPN_SERVER_CERTIFICATE = new ServerCertificate(null);

    protected final Socket socket;
    protected final InputStream inputStream;
    protected final SSLSocketFactory factory;
    protected final int serverPort;

    public SSLVpn(List<ProxyVpn> clients, RootCert rootCert, Socket socket,
           InputStream inputStream, int serverPort) {
        super(clients, rootCert);

        this.socket = socket;
        this.inputStream = inputStream;
        this.serverPort = serverPort;
        try {
            socket.setSoTimeout(60000);
            SSLContext serverContext = SSL_VPN_SERVER_CERTIFICATE.getServerContext(RootCert.load(), getClass().getSimpleName()).newSSLContext();
            factory = serverContext.getSocketFactory();
        } catch(Exception e) {
            throw new IllegalStateException(e);
        }
    }

    protected final HttpResponse notFound() {
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.add("Connection", "close");
        headers.add("Server", getHttpServerName());
        return new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND, headers);
    }

    protected final HttpResponse fullResponse(String contentType, byte[] data) {
        HttpHeaders headers = new DefaultHttpHeaders();
        if (contentType != null) {
            headers.add("Content-Type", contentType);
        }
        headers.add("Content-Length", String.valueOf(data.length));
        headers.add("Connection", "close");
        headers.add("Server", getHttpServerName());
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(data), headers,
                DefaultHttpHeadersFactory.trailersFactory().newEmptyHeaders());
    }

    protected final void writeResponse(OutputStream outputStream, HttpResponse response) throws IOException {
        StringWriter buffer = new StringWriter();
        PrintWriter writer = new PrintWriter(buffer);
        writer.write(response.protocolVersion().toString());
        writer.write(" ");
        writer.write(response.status().toString());
        writer.write("\r\n");
        response.headers().entries().forEach(entry -> {
            writer.write(entry.getKey());
            writer.write(": ");
            writer.write(entry.getValue());
            writer.write("\r\n");
        });
        writer.write("\r\n");
        outputStream.write(buffer.toString().getBytes(StandardCharsets.UTF_8));
        if (response instanceof HttpContent) {
            HttpContent httpContent = (HttpContent) response;
            try(InputStream in = new ByteBufInputStream(httpContent.content())) {
                IoUtil.copy(in, outputStream);
            }
        }
        outputStream.flush();
    }

    protected String getHttpServerName() {
        return getClass().getName();
    }

    @Override
    protected final void stop() {
        IoUtil.close(socket);
    }

    @Override
    public final ClientOS getClientOS() {
        return ClientOS.SSLVpn;
    }

    @Override
    public final InetSocketAddress getRemoteSocketAddress() {
        return (InetSocketAddress) socket.getRemoteSocketAddress();
    }

}

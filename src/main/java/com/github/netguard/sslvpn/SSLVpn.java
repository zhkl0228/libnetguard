package com.github.netguard.sslvpn;

import cn.hutool.core.io.IoUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.github.netguard.IPUtil;
import com.github.netguard.ProxyVpn;
import com.github.netguard.sslvpn.qianxin.QianxinVPN;
import com.github.netguard.vpn.ClientOS;
import com.github.netguard.vpn.tcp.ClientHelloRecord;
import com.github.netguard.vpn.tcp.RootCert;
import com.github.netguard.vpn.tcp.ServerCertificate;
import com.github.netguard.vpn.tls.TlsSignature;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public abstract class SSLVpn extends ProxyVpn {

    private static final Logger log = LoggerFactory.getLogger(SSLVpn.class);

    protected static final List<String> DNS_LIST = Arrays.asList("8.8.8.8", "8.8.4.4");

    private static final ServerCertificate SSL_VPN_SERVER_CERTIFICATE = new ServerCertificate(null);

    public static SSLVpn newSSLVpn(List<ProxyVpn> clients, RootCert rootCert, Socket socket,
                                   InputStream inputStream, int serverPort, ClientHelloRecord clientHelloRecord) {
        TlsSignature tlsSignature = clientHelloRecord.getJa3();
        if (log.isDebugEnabled()) {
            log.debug("{}", String.format("newSSLVpn ja3n_hash=%s, ja4=%s, peetprint_hash=%s, ScrapflyFP=%s",
                    DigestUtil.md5Hex(tlsSignature.getJa3nText()),
                    tlsSignature.getJa4Text(),
                    DigestUtil.md5Hex(tlsSignature.getPeetPrintText()),
                    DigestUtil.md5Hex(tlsSignature.getScrapflyFP())));
        }
        return new QianxinVPN(clients, rootCert, socket, inputStream, serverPort);
    }

    private final Socket socket;
    private final InputStream inputStream;
    private final SSLSocketFactory factory;
    protected final int serverPort;

    public SSLVpn(List<ProxyVpn> clients, RootCert rootCert, Socket socket,
           InputStream inputStream, int serverPort) {
        super(clients, rootCert);

        this.socket = socket;
        this.inputStream = inputStream;
        this.serverPort = serverPort;
        try {
            SSLContext serverContext = SSL_VPN_SERVER_CERTIFICATE.getServerContext(RootCert.load(), getClass().getSimpleName()).newSSLContext();
            this.factory = serverContext.getSocketFactory();
        } catch(Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected final void doRunVpn() {
        try (SSLSocket socket = (SSLSocket) factory.createSocket(this.socket, this.inputStream, true)) {
            socket.setUseClientMode(false);

            final CountDownLatch countDownLatch = new CountDownLatch(1);
            socket.addHandshakeCompletedListener(event -> {
                try {
                    SSLSession session = event.getSession();
                    log.debug("handshakeCompleted event={}, peerHost={}", event, session.getPeerHost());
                } finally {
                    countDownLatch.countDown();
                }
            });
            socket.startHandshake();
            if (!countDownLatch.await(30, TimeUnit.SECONDS)) {
                throw new IOException("Handshake timed out");
            }

            doSSL(socket);
        } catch(IOException e) {
            log.trace("SSL VPN read", e);
        } catch(Exception e) {
            log.warn("SSL VPN failed", e);
        } finally {
            log.debug("Finish socket: {}", socket);
            clients.remove(this);
        }
    }

    protected abstract void doSSL(SSLSocket socket) throws IOException;

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
        headers.add("Connection", "keep-alive");
        headers.add("Server", getHttpServerName());
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(data), headers,
                DefaultHttpHeadersFactory.trailersFactory().newEmptyHeaders());
    }

    protected final void handleHttp(int tag, DataInputStream dataInput, OutputStream outputStream) throws IOException {
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream(0x10)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeInt(tag);
            byte[] header = new byte[12];
            dataInput.readFully(header);
            dataOutput.write(header);
            HttpRequest request = ClientHelloRecord.detectHttp(baos, dataInput);
            log.debug("handleHttp socket={}, request={}", socket, request);
            if (request != null) {
                HttpResponse response = handleHttpRequest(request);
                log.debug("Handle httpResponse: {}", response);
                if (response != null) {
                    writeResponse(outputStream, response);
                    return;
                }
            }
            throw new IOException("NOT support HTTP: request=" + request);
        }
    }

    protected HttpResponse handleHttpRequest(HttpRequest request) throws IOException {
        throw new UnsupportedEncodingException("request=" + request);
    }

    protected final void writeResponse(OutputStream outputStream, HttpResponse response) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8), false);
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

    protected static List<IPUtil.CIDR> getExcludeIPRanges() {
        // Exclude IP ranges
        List<IPUtil.CIDR> listExclude = new ArrayList<>();

        // DNS address
        for (String ip : DNS_LIST) {
            try {
                Inet4Address dns = (Inet4Address) Inet4Address.getByName(ip);
                listExclude.add(new IPUtil.CIDR(dns.getHostAddress(), 24));
            } catch(UnknownHostException e) {
                throw new RuntimeException(e);
            }
        }

        listExclude.add(new IPUtil.CIDR("127.0.0.0", 8)); // localhost

        // USB tethering 192.168.42.x
        // Wi-Fi tethering 192.168.43.x
        listExclude.add(new IPUtil.CIDR("192.168.42.0", 23));
        // Wi-Fi direct 192.168.49.x
        listExclude.add(new IPUtil.CIDR("192.168.49.0", 24));

        // Broadcast
        listExclude.add(new IPUtil.CIDR("224.0.0.0", 3));

        Collections.sort(listExclude);
        return listExclude;
    }

}

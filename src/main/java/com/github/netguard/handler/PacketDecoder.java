package com.github.netguard.handler;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.URLUtil;
import com.github.netguard.Inspector;
import com.github.netguard.handler.session.SSLProxySession;
import com.github.netguard.handler.session.SSLSessionKey;
import com.github.netguard.handler.session.Session;
import com.github.netguard.handler.session.SessionCreator;
import com.github.netguard.handler.session.SessionFactory;
import com.github.netguard.vpn.AcceptResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.ssl.h2.Http2Filter;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.ethernet.EthernetDecoder;
import org.krakenapps.pcap.decoder.ethernet.EthernetFrame;
import org.krakenapps.pcap.decoder.ethernet.EthernetType;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.http.HttpProcessor;
import org.krakenapps.pcap.decoder.http.HttpRequest;
import org.krakenapps.pcap.decoder.http.HttpResponse;
import org.krakenapps.pcap.decoder.http.WebSocketFrame;
import org.krakenapps.pcap.decoder.http.impl.HttpSession;
import org.krakenapps.pcap.decoder.ip.InternetProtocol;
import org.krakenapps.pcap.decoder.ip.IpDecoder;
import org.krakenapps.pcap.decoder.ipv6.Ipv6Decoder;
import org.krakenapps.pcap.decoder.tcp.ProtocolDetector;
import org.krakenapps.pcap.decoder.tcp.TcpDecoder;
import org.krakenapps.pcap.decoder.tcp.TcpPortProtocolMapper;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKeyImpl;
import org.krakenapps.pcap.decoder.udp.UdpDecoder;
import org.krakenapps.pcap.decoder.udp.UdpPortProtocolMapper;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PacketDecoder implements IPacketCapture, HttpProcessor {

    private static final Logger log = LoggerFactory.getLogger(PacketDecoder.class);

    private final IpDecoder ip;
    private final Ipv6Decoder ipv6;
    private final HttpDecoder httpDecoder;
    private final TcpPortProtocolMapper tcpPortProtocolMapper;

    public PacketDecoder() {
        this.httpDecoder = new HttpDecoder();
        this.httpDecoder.register(this);

        EthernetDecoder eth = new EthernetDecoder();
        ip = new IpDecoder();
        ipv6 = new Ipv6Decoder();
        tcpPortProtocolMapper = new TcpPortProtocolMapper() {
            @Override
            public Protocol detectProtocol(TcpSessionKey key, Buffer data) {
                if (protocolDetector != null) {
                    try {
                        data.mark();
                        ProtocolDetector detector = protocolDetector;
                        Protocol protocol = detector.detectProtocol(key, data);
                        if (protocol != null) {
                            return protocol;
                        }
                    } finally {
                        data.reset();
                    }
                }
                try {
                    data.mark();
                    int length = data.bytesBefore(new byte[] { 0x0d, 0x0a });
                    if (length > 0) {
                        String header = data.getString(length);
                        if (header.endsWith("HTTP/1.1") || header.endsWith("HTTP/1.0")) {
                            return Protocol.HTTP;
                        }
                    }
                } finally {
                    data.reset();
                }
                return super.detectProtocol(key, data);
            }
        };
        final UdpPortProtocolMapper udpPortProtocolMapper = new UdpPortProtocolMapper();
        TcpDecoder tcp = new TcpDecoder(tcpPortProtocolMapper);
        UdpDecoder udp = new UdpDecoder(udpPortProtocolMapper);

        eth.register(EthernetType.IPV4, ip);
        eth.register(EthernetType.IPV6, ipv6);
        ip.register(InternetProtocol.TCP, tcp);
        ip.register(InternetProtocol.UDP, udp);
        ipv6.register(InternetProtocol.TCP, tcp);
        ipv6.register(InternetProtocol.UDP, udp);

        tcpPortProtocolMapper.unregister(8080);
        tcpPortProtocolMapper.register(Protocol.HTTP, httpDecoder);
    }

    @Override
    public void onSocketEstablish(String clientIp, String serverIp, int clientPort, int serverPort) {
        log.debug("onSocketEstablish {}:{} => {}:{}", clientIp, clientPort, serverIp, serverPort);
    }

    @Override
    public void onSocketTx(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        if (log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSocketTx %d bytes %s:%d => %s:%d", data.length, clientIp, clientPort, serverIp, serverPort)));
        } else if (log.isDebugEnabled()) {
            log.debug("onSocketTx {} bytes {}:{} => {}:{}", data.length, clientIp, clientPort, serverIp, serverPort);
        }
    }

    @Override
    public void onSocketRx(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        if (log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSocketRx %d bytes %s:%d => %s:%d", data.length, clientIp, clientPort, serverIp, serverPort)));
        } else if (log.isDebugEnabled()) {
            log.debug("onSocketRx {} bytes {}:{} => {}:{}", data.length, clientIp, clientPort, serverIp, serverPort);
        }
    }

    @Override
    public void onSocketFinish(String clientIp, String serverIp, int clientPort, int serverPort) {
        log.debug("onSocketFinish {}:{} => {}:{}", clientIp, clientPort, serverIp, serverPort);
    }

    private ProtocolDetector protocolDetector;

    @SuppressWarnings("unused")
    public void setProtocolDetector(ProtocolDetector protocolDetector) {
        this.protocolDetector = protocolDetector;
    }

    @SuppressWarnings("unused")
    public void setSessionFactory(final SessionFactory sessionFactory) {
        TcpProcessor processor = new SessionCreator() {
            @Override
            public Session createSession(TcpSession tcp) {
                return sessionFactory.createSession(tcp);
            }
        };
        setUnknownTcpProtocolProcessor(processor);
    }

    public void setUnknownTcpProtocolProcessor(TcpProcessor unknownTcpProtocolProcessor) {
        this.tcpPortProtocolMapper.setUnknownProtocolProcessor(unknownTcpProtocolProcessor);
        this.httpDecoder.setFallbackTcpProcessor(unknownTcpProtocolProcessor);
    }

    @Override
    public final void onPacket(byte[] packetData, String type) {
        try {
            if (pcapFileOutputStream != null) {
                pcapFileOutputStream.writePacket(packetData);
            }

            Buffer data = new ChainBuffer(packetData);
            data.mark();
            byte b1 = data.get();
            byte version = (byte) ((b1 & 0xf0) >> 4);
            switch (version) {
                case 4:
                    data.reset();
                    ip.process(new EthernetFrame(null, data));
                    break;
                case 6:
                    data.reset();
                    ipv6.process(new EthernetFrame(null, data));
                    break;
                default:
                    log.warn("Unsupported raw ip version: {}", version);
                    break;
            }
        } catch (Exception e) {
            log.warn("onPacket type={}", type, e);
        }
    }

    @Override
    public final void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName, String applicationProtocol) {
        log.debug("onSSLProxyEstablish {} {}:{} => {}:{} applicationProtocol={}", hostName, clientIp, clientPort, serverIp, serverPort, applicationProtocol);
        try {
            TcpSessionKey key = new SSLSessionKey(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort, hostName);
            httpDecoder.onEstablish(new SSLProxySession(key, applicationProtocol));
        } catch (Exception e) {
            log.warn("onSSLProxyEstablish", e);
        }
    }

    @Override
    public final void onSSLProxyTx(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        if (log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSSLProxyTX %d bytes %s:%d => %s:%d", data.length, clientIp, clientPort, serverIp, serverPort)));
        }
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.handleTx(key, new ChainBuffer(data));
        } catch (Exception e) {
            log.warn("onSSLProxyTX", e);
        }
    }

    @Override
    public final void onSSLProxyRx(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        if (log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSSLProxyRX %d bytes %s:%d => %s:%d", data.length, clientIp, clientPort, serverIp, serverPort)));
        }
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.handleRx(key, new ChainBuffer(data));
        } catch (Exception e) {
            log.warn("onSSLProxyRX: " + clientIp + ":" + clientPort + " => " + serverIp + ":" + serverPort, e);
        }
    }

    @Override
    public final void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
        log.debug("onSSLProxyFinish {} {}:{} => {}:{}", hostName, clientIp, clientPort, serverIp, serverPort);
        try {
            TcpSessionKey key = new SSLSessionKey(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort, hostName);
            httpDecoder.onFinish(key);
        } catch (Exception e) {
            log.warn("onSSLProxyFinish", e);
        }
    }

    @Override
    public final void onRequest(HttpSession session, HttpRequest request) {
        onRequest(session, new KrakenHttpRequest(request));
    }

    protected void onRequest(HttpSession session, com.github.netguard.handler.http.HttpRequest request) {
        if (log.isDebugEnabled()) {
            byte[] data = request.getPostData();
            log.debug("onRequest {} bytes session={}, request={}\n{}{}\n", data == null ? 0 : data.length, session, request, request.getHeaderString(), parseParameters(request.getRequestUri()));
        }
    }

    @Override
    public final void onResponse(HttpSession session, HttpRequest request, HttpResponse response) {
        onResponse(session, new KrakenHttpRequest(request), new KrakenHttpResponse(response));
    }

    protected void onResponse(HttpSession session, com.github.netguard.handler.http.HttpRequest request, com.github.netguard.handler.http.HttpResponse response) {
        if (log.isDebugEnabled()) {
            byte[] data = response.getResponseData();
            log.debug("onResponse {} bytes session={}, request={}, response={}\n{}", data == null ? 0 : data.length, session, request, response, response.getHeaderString());
        }
    }

    @Override
    public void onMultipartData(HttpSession session, Buffer buffer) {
        log.debug("onMultipartData session={}, buffer={}", session, buffer);
    }

    @Override
    public void onChunkedRequest(HttpSession session, HttpRequest request, Buffer chunked) {
        log.debug("onChunkedRequest session={}, request={}, chunked={}", session, request, chunked);
    }

    @Override
    public void onChunkedResponse(HttpSession session, HttpRequest request, HttpResponse response, Buffer chunked) {
        log.debug("onChunkedResponse session={}, request={}, response={}, chunked={}", session, request, response, chunked);
    }

    @Override
    public void onWebSocketHandshake(HttpSession session, HttpRequest request, HttpResponse response) {
        log.debug("onWebSocketHandshake session={}, request={}, response={}", session, request, response);
    }

    @Override
    public void onWebSocketRequest(HttpSession session, WebSocketFrame frame) {
        log.debug("onWebSocketRequest session={}, frame={}", session, frame);
    }

    @Override
    public void onWebSocketResponse(HttpSession session, WebSocketFrame frame) {
        log.debug("onWebSocketResponse session={}, frame={}", session, frame);
    }

    private PcapFileOutputStream pcapFileOutputStream;

    @SuppressWarnings("unused")
    public void setOutputPcapFile(File pcapFile) throws IOException {
        if (pcapFileOutputStream != null) {
            IoUtil.close(pcapFileOutputStream);
        }
        pcapFileOutputStream = new PcapFileOutputStream(pcapFile);
    }

    @Override
    public void notifyFinish() {
        if (pcapFileOutputStream != null) {
            IoUtil.close(pcapFileOutputStream);
            pcapFileOutputStream = null;
        }
    }

    @Override
    public AcceptResult acceptSSL(String serverIp, int port, String hostName, List<String> applicationLayerProtocols) {
        if (hostName != null) {
            if (hostName.endsWith(".icloud.com") ||
                    hostName.endsWith(".apple.com")) {
                return AcceptResult.builder(AllowRule.CONNECT_TCP).build(); // Enable iOS traffic.
            }
            if (hostName.endsWith(".googleapis.com") ||
                    hostName.endsWith(".google.com") ||
                    "www.gstatic.com".equals(hostName)) {
                return AcceptResult.builder(AllowRule.DISCONNECT).build(); // Disable android traffic.
            }
            return null;
        } else {
            return AcceptResult.builder(AllowRule.CONNECT_TCP).build();
        }
    }

    @Override
    public Http2Filter getH2Filter() {
        return null;
    }

    public static Map<String, String> parseParameters(String parameters) {
        int index = parameters.lastIndexOf('?');
        if (index != -1) {
            parameters = parameters.substring(index + 1);
        }
        String[] values = parameters.split("&");
        Map<String, String> map = new LinkedHashMap<>();
        for (String pair : values) {
            index = pair.indexOf('=');
            if (index == -1) {
                log.debug("parseParameters failed {}", parameters);
                continue;
            }
            String name = pair.substring(0, index);
            String value = pair.substring(index + 1);
            map.put(name, URLUtil.decode(value, StandardCharsets.UTF_8));
        }
        return map;
    }
}

package com.github.netguard.handler;

import com.github.netguard.handler.session.SSLProxySession;
import com.github.netguard.handler.session.Session;
import com.github.netguard.handler.session.SessionCreator;
import com.github.netguard.handler.session.SessionFactory;
import com.github.netguard.vpn.IPacketCapture;
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

import java.net.InetAddress;

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

    private ProtocolDetector protocolDetector;

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
    public final void onSSLProxyEstablish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
        log.debug("onSSLProxyEstablish {} {}:{} => {}:{}", hostName, clientIp, clientPort, serverIp, serverPort);
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.onEstablish(new SSLProxySession(key, hostName));
        } catch (Exception e) {
            log.warn("onSSLProxyEstablish", e);
        }
    }

    @Override
    public final void onSSLProxyTX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        log.trace("onSSLProxyTX {}:{} => {}:{}", clientIp, clientPort, serverIp, serverPort);
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.handleTx(key, new ChainBuffer(data));
        } catch (Exception e) {
            log.warn("onSSLProxyTX", e);
        }
    }

    @Override
    public final void onSSLProxyRX(String clientIp, String serverIp, int clientPort, int serverPort, byte[] data) {
        log.trace("onSSLProxyRX {}:{} => {}:{}", clientIp, clientPort, serverIp, serverPort);
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.handleRx(key, new ChainBuffer(data));
        } catch (Exception e) {
            log.warn("onSSLProxyRX", e);
        }
    }

    @Override
    public final void onSSLProxyFinish(String clientIp, String serverIp, int clientPort, int serverPort, String hostName) {
        log.debug("onSSLProxyFinish {} {}:{} => {}:{}", hostName, clientIp, clientPort, serverIp, serverPort);
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(clientIp), InetAddress.getByName(serverIp), clientPort, serverPort);
            httpDecoder.onFinish(key);
        } catch (Exception e) {
            log.warn("onSSLProxyFinish", e);
        }
    }

    @Override
    public void onRequest(HttpSession session, HttpRequest request) {
        log.trace("onRequest session={}, request={}", session, request);
    }

    @Override
    public void onResponse(HttpSession session, HttpRequest request, HttpResponse response) {
        log.trace("onResponse session={}, request={}, response={}", session, request, response);
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

}

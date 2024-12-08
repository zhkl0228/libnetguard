package com.github.netguard.handler;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.URLUtil;
import com.github.netguard.Inspector;
import com.github.netguard.handler.replay.FileReplay;
import com.github.netguard.handler.replay.Replay;
import com.github.netguard.handler.session.SSLProxySession;
import com.github.netguard.handler.session.SSLSessionKey;
import com.github.netguard.handler.session.Session;
import com.github.netguard.handler.session.SessionCreator;
import com.github.netguard.handler.session.SessionFactory;
import com.github.netguard.vpn.AcceptTcpResult;
import com.github.netguard.vpn.AcceptUdpResult;
import com.github.netguard.vpn.AllowRule;
import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.tcp.ConnectRequest;
import com.github.netguard.vpn.tcp.h2.Http2Filter;
import com.github.netguard.vpn.udp.DNSFilter;
import com.github.netguard.vpn.udp.PacketRequest;
import com.github.netguard.vpn.udp.quic.QuicProxyProvider;
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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

public class PacketDecoder implements IPacketCapture, HttpProcessor {

    private static final Logger log = LoggerFactory.getLogger(PacketDecoder.class);

    private final Logger iLog = LoggerFactory.getLogger(getClass());

    private final IpDecoder ip;
    private final Ipv6Decoder ipv6;
    private final HttpDecoder httpDecoder;
    private final TcpPortProtocolMapper tcpPortProtocolMapper;

    public PacketDecoder() {
        this(true);
    }

    private final boolean decodePacket;

    public PacketDecoder(boolean decodePacket) {
        this.decodePacket = decodePacket;
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
    public void onSocketEstablish(InetSocketAddress client, InetSocketAddress server) {
        iLog.debug("onSocketEstablish {} => {}", client, server);
    }

    @Override
    public void onSocketTx(InetSocketAddress client, InetSocketAddress server, byte[] data) {
        if (iLog.isTraceEnabled() || log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSocketTx %d bytes %s => %s", data.length, client, server)));
        } else if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            log.debug("onSocketTx {} bytes {} => {}", data.length, client, server);
        }
    }

    @Override
    public void onSocketRx(InetSocketAddress client, InetSocketAddress server, byte[] data) {
        if (iLog.isTraceEnabled() || log.isTraceEnabled()) {
            byte[] tmp;
            if (data.length > 256) {
                tmp = Arrays.copyOf(data, 256);
            } else {
                tmp = data;
            }
            log.trace(Inspector.inspectString(tmp, String.format("onSocketRx %d bytes %s => %s", data.length, client, server)));
        } else if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            log.debug("onSocketRx {} bytes {} => {}", data.length, client, server);
        }
    }

    @Override
    public void onSocketFinish(InetSocketAddress client, InetSocketAddress server) {
        iLog.debug("onSocketFinish {} => {}", client, server);
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
        if (!decodePacket) {
            return;
        }

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
                    iLog.warn("Unsupported raw ip version: {}", version);
                    break;
            }
        } catch (Exception e) {
            iLog.warn("onPacket type={}", type, e);
        }
    }

    @Override
    public final void onSSLProxyEstablish(InetSocketAddress client, InetSocketAddress server, String hostName,
                                          Collection<String> applicationProtocols, String selectedApplicationProtocol, String application) {
        iLog.trace("onSSLProxyEstablish {} {} => {} selectedApplicationProtocol={}", hostName, client, server, selectedApplicationProtocol);
        try {
            TcpSessionKey key = new SSLSessionKey(client.getAddress(), server.getAddress(), client.getPort(), server.getPort(), hostName);
            httpDecoder.onEstablish(new SSLProxySession(key, hostName, applicationProtocols, selectedApplicationProtocol, application));
        } catch (Exception e) {
            iLog.warn("onSSLProxyEstablish", e);
        }
    }

    @Override
    public void onSSLProxyTx(InetSocketAddress client, InetSocketAddress server, byte[] data) {
        if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            byte[] tmp;
            if (iLog.isTraceEnabled() || log.isTraceEnabled() || data.length <= 256) {
                tmp = data;
            } else {
                tmp = Arrays.copyOf(data, 256);
            }
            log.debug(Inspector.inspectString(tmp, String.format("onSSLProxyTX %d bytes %s => %s, data=%s", data.length, client, server, Base64.encode(data))));
        }
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(client.getAddress(), server.getAddress(), client.getPort(), server.getPort());
            httpDecoder.handleTx(key, new ChainBuffer(data));
        } catch (Exception e) {
            iLog.warn("onSSLProxyTX", e);
        }
    }

    @Override
    public void onSSLProxyRx(InetSocketAddress client, InetSocketAddress server, byte[] data) {
        if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            byte[] tmp;
            if (iLog.isTraceEnabled() || log.isTraceEnabled() || data.length <= 256) {
                tmp = data;
            } else {
                tmp = Arrays.copyOf(data, 256);
            }
            log.debug(Inspector.inspectString(tmp, String.format("onSSLProxyRX %d bytes %s => %s, data=%s", data.length, client, server, Base64.encode(data))));
        }
        try {
            TcpSessionKey key = new TcpSessionKeyImpl(client.getAddress(), server.getAddress(), client.getPort(), server.getPort());
            httpDecoder.handleRx(key, new ChainBuffer(data));
        } catch (Exception e) {
            iLog.warn("onSSLProxyRX: {} => {}", client, server, e);
        }
    }

    @Override
    public final void onSSLProxyFinish(InetSocketAddress client, InetSocketAddress server, String hostName) {
        iLog.trace("onSSLProxyFinish {} {} => {}", hostName, client, server);
        try {
            TcpSessionKey key = new SSLSessionKey(client.getAddress(), server.getAddress(), client.getPort(), server.getPort(), hostName);
            httpDecoder.onFinish(key);
        } catch (Exception e) {
            iLog.warn("onSSLProxyFinish", e);
        }
    }

    @Override
    public final void onRequest(HttpSession session, HttpRequest request) {
        onRequest(session, new KrakenHttpRequest(request));
    }

    protected void onRequest(HttpSession session, com.github.netguard.handler.http.HttpRequest request) {
        if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            byte[] data = request.getPostData();
            log.debug("onRequest {} bytes session={}, application={}, request={}\n{}{}\n", data == null ? 0 : data.length, session, session.getApplication(), request, request.getHeaderString(), parseParameters(request.getRequestUri()));
        }
    }

    @Override
    public final void onResponse(HttpSession session, HttpRequest request, HttpResponse response) {
        onResponse(session, new KrakenHttpRequest(request), new KrakenHttpResponse(response));
    }

    protected void onResponse(HttpSession session, com.github.netguard.handler.http.HttpRequest request, com.github.netguard.handler.http.HttpResponse response) {
        if (iLog.isDebugEnabled() || log.isDebugEnabled()) {
            byte[] data = response.getResponseData();
            log.debug("onResponse {} bytes session={}, application={}, requestUri={}, response={}\nResponse code: {} {}\n{}", data == null ? 0 : data.length, session, session.getApplication(), request.getRequestUri(), response, response.getResponseCode(), response.getResponseCodeMsg(), response.getHeaderString());
        }
    }

    @Override
    public void onMultipartData(HttpSession session, Buffer buffer) {
        iLog.debug("onMultipartData session={}, buffer={}", session, buffer);
    }

    @Override
    public void onChunkedRequest(HttpSession session, HttpRequest request, Buffer chunked) {
        iLog.debug("onChunkedRequest session={}, requestURL={}, chunked={}", session, request.getURL(), chunked);
    }

    @Override
    public void onChunkedResponse(HttpSession session, HttpRequest request, HttpResponse response, Buffer chunked) {
        iLog.debug("onChunkedResponse session={}, requestURL={}, response={}, chunked={}", session, request.getURL(), response, chunked);
    }

    @Override
    public void onWebSocketHandshake(HttpSession session, HttpRequest request, HttpResponse response) {
        iLog.debug("onWebSocketHandshake session={}, requestURL={}, response={}", session, request.getURL(), response);
    }

    @Override
    public void onWebSocketRequest(HttpSession session, WebSocketFrame frame) {
        iLog.debug("onWebSocketRequest session={}, frame={}", session, frame);
    }

    @Override
    public void onWebSocketResponse(HttpSession session, WebSocketFrame frame) {
        iLog.debug("onWebSocketResponse session={}, frame={}", session, frame);
    }

    private PcapFileOutputStream pcapFileOutputStream;

    protected final void setOutputPcapFile(File pcapFile) throws IOException {
        if (pcapFileOutputStream != null) {
            IoUtil.close(pcapFileOutputStream);
        }
        pcapFileOutputStream = new PcapFileOutputStream(pcapFile);
    }

    @Override
    public void replay(Replay replay) {
        if(replay != null) {
            replay.doReplay(httpDecoder);
            httpDecoder.setTcpVisitor(replay);
        }
    }

    @Override
    public void notifyVpnFinish() {
        if (pcapFileOutputStream != null) {
            IoUtil.close(pcapFileOutputStream);
            pcapFileOutputStream = null;
        }
    }

    @Override
    public AcceptTcpResult acceptTcp(ConnectRequest connectRequest) {
        iLog.debug("acceptTcp connectRequest={}", connectRequest);
        if (connectRequest.isAppleHost()) {
            return configAcceptResultBuilder(connectRequest.hostName, connectRequest.port, connectRequest.connectTcpDirect()).build(); // Enable iOS traffic.
        }
        if (connectRequest.isAndroidHost()) {
            return connectRequest.disconnect(); // Disable android traffic.
        }
        if (connectRequest.isSSL()) {
            return null;
        } else {
            return configAcceptResultBuilder(null, connectRequest.port, AcceptTcpResult.builder(AllowRule.CONNECT_TCP)).build();
        }
    }

    @Override
    public AcceptUdpResult acceptUdp(PacketRequest packetRequest) {
        return null;
    }

    @SuppressWarnings("unused")
    protected AcceptTcpResult.AcceptResultBuilder configAcceptResultBuilder(String hostName, int port, AcceptTcpResult.AcceptResultBuilder builder) {
        return builder;
    }

    @Override
    public Http2Filter getH2Filter() {
        return null;
    }

    @Override
    public DNSFilter getDNSFilter() {
        return null;
    }

    @Override
    public QuicProxyProvider getQuicProxyProvider() {
        return QuicProxyProvider.netty();
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
                log.trace("parseParameters failed: parameters=\"{}\"", parameters);
                continue;
            }
            String name = pair.substring(0, index);
            String value = pair.substring(index + 1);
            map.put(name, URLUtil.decode(value, StandardCharsets.UTF_8));
        }
        return map;
    }

    @SuppressWarnings("unused")
    public static boolean isVpnConnected() {
        try {
            Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
            while (enumeration.hasMoreElements()) {
                NetworkInterface networkInterface = enumeration.nextElement();
                if (networkInterface.isLoopback() ||
                        !networkInterface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addressEnumeration = networkInterface.getInetAddresses();
                while (addressEnumeration.hasMoreElements()) {
                    InetAddress address = addressEnumeration.nextElement();
                    if (address instanceof Inet6Address) {
                        continue;
                    }
                    if (networkInterface.isPointToPoint()) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return false;
    }
}

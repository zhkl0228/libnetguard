package com.github.netguard.vpn.ssl;

import com.github.netguard.vpn.InspectorVpn;
import eu.faircode.netguard.Packet;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.ReadOnlyHttpHeaders;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ClientHelloRecord {

    private static final Logger log = LoggerFactory.getLogger(ClientHelloRecord.class);

    private static final int PROLOGUE_MAX_LENGTH = 128;

    static ClientHelloRecord prologue(ByteArrayOutputStream baos, DataInputStream dataInput) throws IOException {
        int available = dataInput.available();
        int count = PROLOGUE_MAX_LENGTH - baos.size();
        if (available > 0 && count > 0) {
            byte[] buf = new byte[Math.min(count, available)];
            dataInput.readFully(buf);
            baos.write(buf);
        }
        ClientHelloRecord http = detectHttp(baos, dataInput);
        if (http != null) {
            return http;
        }
        return new ClientHelloRecord(baos.toByteArray(), null);
    }

    private static ClientHelloRecord detectHttp(ByteArrayOutputStream baos, DataInputStream dataInput) throws IOException {
        byte[] data = baos.toByteArray();
        Buffer buffer = new ChainBuffer(data);
        if (!buffer.isEOB()) {
            int index = buffer.bytesBefore(new byte[] { 0x20, 0x2f }); // "XXX /"
            log.debug("detectHttp index={}, baos={}", index, baos);
            if (index >= 3) {
                String method = buffer.getString(index);
                HttpMethod httpMethod = null;
                switch (method) {
                    case "POST":
                        httpMethod = HttpMethod.POST;
                        break;
                    case "GET":
                        httpMethod = HttpMethod.GET;
                        break;
                    case "PUT":
                        httpMethod = HttpMethod.PUT;
                        break;
                    case "DELETE":
                        httpMethod = HttpMethod.DELETE;
                        break;
                    case "HEAD":
                        httpMethod = HttpMethod.HEAD;
                        break;
                    case "OPTIONS":
                        httpMethod = HttpMethod.OPTIONS;
                        break;
                    case "TRACE":
                        httpMethod = HttpMethod.TRACE;
                        break;
                    case "CONNECT":
                        httpMethod = HttpMethod.CONNECT;
                        break;
                    case "PATCH":
                        httpMethod = HttpMethod.PATCH;
                        break;
                }
                if (httpMethod != null) {
                    try {
                        return decodeHttpRequest(baos, dataInput, httpMethod);
                    } catch (RuntimeException e) {
                        log.warn("decodeHttpRequest httpMethod={}, baos={}", httpMethod, baos, e);
                    }
                }
            }
        }
        return null;
    }

    private static ClientHelloRecord decodeHttpRequest(ByteArrayOutputStream baos, DataInputStream dataInput, HttpMethod httpMethod) throws IOException {
        log.debug("decodeHttpRequest httpMethod={}", httpMethod);
        PrologueInputStream inputStream = new PrologueInputStream(baos, dataInput);
        for (byte b : httpMethod.name().getBytes()) {
            byte read = (byte) inputStream.read();
            if (read != b) {
                throw new IllegalStateException("httpMethod=" + httpMethod);
            }
        }
        if (inputStream.read() != ' ') {
            throw new IllegalStateException("httpMethod=" + httpMethod + ", baos=" + baos);
        }
        String uri = null;
        HttpVersion version = null;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        {
            while(true) {
                int b = inputStream.read();
                if (b == '\n') {
                    String line = buffer.toString().trim();
                    int index = line.lastIndexOf(' ');
                    if (index != -1) {
                        uri = line.substring(0, index);
                        version = HttpVersion.valueOf(line.substring(index + 1));
                    }
                    break;
                } else {
                    buffer.write(b);
                }
            }
        }
        log.debug("decodeHttpRequest uri={}, version={}", uri, version);
        if (uri != null && version != null) {
            buffer.reset();
            boolean end = false;
            List<CharSequence> nameValuePairs = new ArrayList<>();
            while (true) {
                int b = inputStream.read();
                if (b == '\n') {
                    if (end) {
                        break;
                    } else {
                        end = true;

                        String line = buffer.toString().trim();
                        buffer.reset();
                        int index = line.lastIndexOf(':');
                        if (index == -1) {
                            return null;
                        }
                        String name = line.substring(0, index).trim();
                        String value = line.substring(index + 1).trim();
                        log.debug("decodeHttpRequest name={}, value={}", name, value);
                        nameValuePairs.add(name);
                        nameValuePairs.add(value);
                    }
                } else {
                    buffer.write(b);
                    if (b != '\r') {
                        end = false;
                    }
                }
            }
            HttpHeaders headers = new ReadOnlyHttpHeaders(false, nameValuePairs.toArray(new CharSequence[0]));
            HttpRequest httpRequest = new DefaultHttpRequest(version, httpMethod, uri, headers);
            log.debug("decodeHttpRequest httpRequest={}, nameValuePairs={}", httpRequest, nameValuePairs);
            return new ClientHelloRecord(baos.toByteArray(), httpRequest);
        }
        return null;
    }

    ConnectRequest newConnectRequest(InspectorVpn vpn, Packet packet) {
        return new ConnectRequest(vpn, packet, this.hostName, this.applicationLayerProtocols, this.prologue, httpRequest);
    }

    public final byte[] prologue;
    public final String hostName;
    public final List<String> applicationLayerProtocols;
    private final HttpRequest httpRequest;

    private ClientHelloRecord(byte[] prologue, HttpRequest httpRequest) {
        this(prologue, null, new ArrayList<>(0), httpRequest);
    }

    ClientHelloRecord(byte[] prologue, String hostName, List<String> applicationLayerProtocols, HttpRequest httpRequest) {
        this.prologue = prologue;
        this.hostName = hostName;
        this.applicationLayerProtocols = applicationLayerProtocols;
        this.httpRequest = httpRequest;
    }

    @Override
    public String toString() {
        return "ClientHelloRecord{" +
                "hostName='" + hostName + '\'' +
                ", applicationLayerProtocols='" + applicationLayerProtocols + '\'' +
                '}';
    }
}

package com.github.netguard.handler;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Set;

import org.krakenapps.pcap.decoder.http.HttpHeaders;
import org.krakenapps.pcap.decoder.http.HttpRequest;

class KrakenHttpRequest implements com.github.netguard.handler.http.HttpRequest {
    private final HttpRequest request;
    KrakenHttpRequest(HttpRequest request) {
        super();
        this.request = request;
    }
    @Override
    public String getHeaderString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append(getRequestLine()).append('\n');
        for(String name : request.getHeaderKeys()) {
            buffer.append(name).append(": ").append(request.getHeader(name)).append('\n');
        }
        return buffer.toString();
    }

    @Override
    public Set<String> getHeaderKeys() {
        return request.getHeaderKeys();
    }

    @Override
    public String getRequestLine() {
        StringBuilder buffer = new StringBuilder();
        buffer.append(request.getMethod()).append(' ').append(getRequestUri());
        if(request.getQueryString() != null) {
            buffer.append('?').append(request.getQueryString());
        }
        buffer.append(' ');
        switch (request.getHttpVersion()) {
            case HTTP_1_0:
                buffer.append("HTTP/1.0");
                break;
            case HTTP_1_1:
                buffer.append("HTTP/1.1");
                break;
        }
        return buffer.toString();
    }
    @Override
    public String getHeader(String name) {
        return getHeader(request, name);
    }
    @Override
    public String getScheme() {
        return request.getURL().getProtocol();
    }
    @Override
    public String getHost() {
        String host = getHeader(request, HttpHeaders.HOST);
        if (host != null) {
            return host;
        }
        URL url = request.getURL();
        return url.getHost();
    }

    @Override
    public int getPort() {
        return request.getServerAddress().getPort();
    }

    @Override
    public String getRequestUri() {
        StringBuilder buffer = new StringBuilder();
        buffer.append(request.getURL().getPath());
        String queryString = request.getQueryString();
        if(queryString != null) {
            buffer.append('?');
            try {
                buffer.append(URLDecoder.decode(queryString, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                buffer.append(queryString);
            }
        }
        return buffer.toString();
    }
    @Override
    public String getRequestMethod() {
        return String.valueOf(request.getMethod());
    }
    @Override
    public String getContentType() {
        return getHeader(HttpHeaders.CONTENT_TYPE);
    }
    @Override
    public byte[] getPostData() {
        return request.getRequestEntity();
    }

    private static String getHeader(HttpRequest request, String name) {
        for(String key : request.getHeaderKeys()) {
            if(key.equalsIgnoreCase(name)) {
                return request.getHeader(key);
            }
        }
        return null;
    }
}
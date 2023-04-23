package com.github.netguard.handler;

import cn.hutool.core.io.IoUtil;
import org.krakenapps.pcap.decoder.http.HttpHeaders;
import org.krakenapps.pcap.decoder.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Set;

class KrakenHttpResponse implements com.github.netguard.handler.http.HttpResponse {
    private final HttpResponse response;
    KrakenHttpResponse(HttpResponse response) {
        super();
        this.response = response;
    }
    @Override
    public String getHeaderString() {
        StringBuilder buffer = new StringBuilder();
        for(String name : response.getHeaderKeys()) {
            buffer.append(name).append(": ").append(response.getHeader(name)).append('\n');
        }
        return buffer.toString();
    }

    @Override
    public Set<String> getHeaderKeys() {
        return response.getHeaderKeys();
    }

    @Override
    public String getHeader(String name) {
        return getHeader(response, name);
    }
    @Override
    public int getResponseCode() {
        return response.getStatusCode();
    }
    @Override
    public String getResponseCodeMsg() {
        String statusCode = Integer.toString(getResponseCode());
        return response.getStatusLine().substring(statusCode.length()).trim();
    }
    @Override
    public String getRequestVersion() {
        switch (response.getHttpVersion()) {
            case HTTP_1_0:
                return "HTTP/1.0";
            case HTTP_1_1:
                return "HTTP/1.1";
        }
        throw new UnsupportedOperationException("Unsupported http version: " + response.getHttpVersion());
    }
    @Override
    public String getContentEncoding() {
        return getHeader(HttpHeaders.CONTENT_ENCODING);
    }
    @Override
    public String getTransferEncoding() {
        return getHeader(HttpHeaders.TRANSFER_ENCODING);
    }
    @Override
    public String getContentType() {
        return getHeader(HttpHeaders.CONTENT_TYPE);
    }

    private static final Logger log = LoggerFactory.getLogger(KrakenHttpResponse.class);

    private byte[] responseData;

    @Override
    public byte[] getResponseData() {
        if(responseData != null) {
            return responseData;
        }

        try (InputStream inputStream = response.getInputStream()) {
            if(inputStream == null) {
                return null;
            }
            responseData = IoUtil.readBytes(inputStream);
            return responseData;
        } catch(Exception e) {
            log.warn(e.getMessage(), e);
            return null;
        }
    }

    private static String getHeader(HttpResponse response, String name) {
        for(String key : response.getHeaderKeys()) {
            if(key.equalsIgnoreCase(name)) {
                return response.getHeader(key);
            }
        }
        return null;
    }
}
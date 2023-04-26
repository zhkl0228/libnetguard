package com.github.netguard.vpn.ssl.h2;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

public interface Http2Filter {

    boolean acceptHost(String hostName);

    byte[] filterRequest(Http2SessionKey sessionKey, HttpRequest request, HttpHeaders headers, byte[] requestData);

    byte[] filterResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData);

    byte[] filterPollingRequest(Http2SessionKey sessionKey, HttpRequest request, HttpHeaders headers, byte[] requestData);

    byte[] filterPollingResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData, boolean endStream);

}

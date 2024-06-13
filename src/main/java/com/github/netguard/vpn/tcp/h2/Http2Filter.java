package com.github.netguard.vpn.tcp.h2;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

public interface Http2Filter {

    /**
     * 是否过滤对应 hostName 的 http2 请求与响应
     * @return <code>true</code>才会针对特定主机名的请求与响应执行 filter_* 过滤
     */
    boolean filterHost(String hostName);

    byte[] filterRequest(Http2SessionKey sessionKey, HttpRequest request, HttpHeaders headers, byte[] requestData);

    byte[] filterResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData);

    byte[] filterPollingRequest(Http2SessionKey sessionKey, HttpRequest request, byte[] requestData, boolean newStream);

    byte[] filterPollingResponse(Http2SessionKey sessionKey, HttpResponse response, byte[] responseData, boolean endStream);

    /**
     * 针对需要过滤的 http2 请求，是否取消执行
     * @return <code>true</code>则会取消该请求的执行
     */
    CancelResult cancelRequest(HttpRequest request, byte[] requestData, boolean polling);

}

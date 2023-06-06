package com.github.netguard.vpn.ssl.h2;

import cn.hutool.core.util.ZipUtil;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public abstract class AbstractHttp2Filter implements Http2Filter {

    private static class RequestData {
        final HttpRequest request;
        final byte[] requestData;
        RequestData(HttpRequest request, byte[] requestData) {
            this.request = request;
            this.requestData = requestData;
        }
    }

    private final Map<Http2SessionKey, RequestData> requestMap = new HashMap<>();

    @Override
    public final byte[] filterRequest(Http2SessionKey sessionKey, HttpRequest request, HttpHeaders headers, byte[] requestData) {
        String contentEncoding = headers.get("content-encoding");
        boolean isDeflate = "deflate".equalsIgnoreCase(contentEncoding);
        byte[] data = isDeflate ? ZipUtil.unZlib(requestData) : requestData;
        requestMap.put(sessionKey, new RequestData(request, data));
        byte[] fakeRequestData = filterRequestInternal(request, data);
        if (isDeflate) {
            fakeRequestData = ZipUtil.zlib(fakeRequestData, 9);
        }
        if (fakeRequestData.length != requestData.length &&
                headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
            headers.setInt(HttpHeaderNames.CONTENT_LENGTH, fakeRequestData.length);
        }
        return fakeRequestData;
    }

    protected byte[] filterRequestInternal(HttpRequest request, byte[] requestData) {
        return requestData;
    }

    @Override
    public final byte[] filterResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData) {
        RequestData data = requestMap.remove(sessionKey);
        if (data == null) {
            return responseData;
        }
        byte[] fakeResponseData = filterResponseInternal(data.request, data.requestData, response, responseData);
        if (fakeResponseData.length != responseData.length &&
                headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
            headers.setInt(HttpHeaderNames.CONTENT_LENGTH, fakeResponseData.length);
        }
        return fakeResponseData;
    }

    protected abstract byte[] filterResponseInternal(HttpRequest request, byte[] requestData, HttpResponse response, byte[] responseData);

    @Override
    public final byte[] filterPollingRequest(Http2SessionKey sessionKey, HttpRequest request, byte[] requestData, boolean newStream) {
        requestMap.put(sessionKey, new RequestData(request, requestData));
        return filterPollingRequestInternal(request, requestData, newStream);
    }

    protected byte[] filterPollingRequestInternal(HttpRequest request, byte[] requestData, boolean newStream) {
        return requestData;
    }

    @Override
    public final byte[] filterPollingResponse(Http2SessionKey sessionKey, HttpResponse response, byte[] responseData, boolean endStream) {
        RequestData data = endStream ? requestMap.remove(sessionKey) : requestMap.get(sessionKey);
        if (data == null) {
            return responseData;
        }
        return filterPollingResponseInternal(data.request, response, responseData);
    }

    protected abstract byte[] filterPollingResponseInternal(HttpRequest request, HttpResponse response, byte[] responseData);

    @Override
    public boolean acceptRequest(HttpRequest request, byte[] requestData, boolean polling) {
        return true;
    }

}

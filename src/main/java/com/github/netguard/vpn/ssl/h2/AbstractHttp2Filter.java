package com.github.netguard.vpn.ssl.h2;

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
        requestMap.put(sessionKey, new RequestData(request, requestData));
        return filterRequestInternal(request, headers, requestData);
    }

    protected byte[] filterRequestInternal(HttpRequest request, HttpHeaders headers, byte[] requestData) {
        return requestData;
    }

    @Override
    public final byte[] filterResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData) {
        RequestData data = requestMap.remove(sessionKey);
        if (data == null) {
            return responseData;
        }
        return filterResponseInternal(data.request, data.requestData, response, headers, responseData);
    }

    protected abstract byte[] filterResponseInternal(HttpRequest request, byte[] requestData, HttpResponse response, HttpHeaders headers, byte[] responseData);

    @Override
    public final byte[] filterPollingRequest(Http2SessionKey sessionKey, HttpRequest request, HttpHeaders headers, byte[] requestData, boolean newStream) {
        requestMap.put(sessionKey, new RequestData(request, requestData));
        return filterPollingRequestInternal(request, headers, requestData, newStream);
    }

    protected byte[] filterPollingRequestInternal(HttpRequest request, HttpHeaders headers, byte[] requestData, boolean newStream) {
        return requestData;
    }

    @Override
    public final byte[] filterPollingResponse(Http2SessionKey sessionKey, HttpResponse response, HttpHeaders headers, byte[] responseData, boolean endStream) {
        RequestData data = endStream ? requestMap.remove(sessionKey) : requestMap.get(sessionKey);
        if (data == null) {
            return responseData;
        }
        return filterPollingResponseInternal(data.request, data.requestData, response, headers, responseData);
    }

    protected abstract byte[] filterPollingResponseInternal(HttpRequest request, byte[] requestData, HttpResponse response, HttpHeaders headers, byte[] responseData);

}

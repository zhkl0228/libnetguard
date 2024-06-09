package com.github.netguard.vpn.ssl.h2;

import cn.hutool.core.io.IORuntimeException;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ZipUtil;
import com.alibaba.fastjson.JSONObject;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@SuppressWarnings("unused")
public abstract class AbstractHttp2Filter implements Http2Filter {

    private static final Logger log = LoggerFactory.getLogger(AbstractHttp2Filter.class);

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
        byte[] fakeRequestData = filterRequestInternal(request, headers, requestData);
        if (fakeRequestData.length != requestData.length &&
                headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
            headers.setInt(HttpHeaderNames.CONTENT_LENGTH, fakeRequestData.length);
        }
        headers.set(":method", request.method().name());
        headers.set(":path", request.uri());
        return fakeRequestData;
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
        byte[] fakeResponseData = filterResponseInternal(data.request, data.requestData, response, responseData);
        if (fakeResponseData.length != responseData.length &&
                headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
            headers.setInt(HttpHeaderNames.CONTENT_LENGTH, fakeResponseData.length);
        }
        return fakeResponseData;
    }

    /**
     * 序列化请求与响应
     */
    protected final JSONObject serializeRequest(HttpRequest request, byte[] requestData, HttpResponse response, byte[] responseData) {
        JSONObject obj = new JSONObject(true);
        obj.put("method", request.method().name());
        obj.put("uri", request.uri());
        obj.put("requestHeaders", createHeadersObject(request.headers()));
        obj.put("requestData", requestData);
        obj.put("responseCode", response.status().code());
        obj.put("responseHeaders", createHeadersObject(response.headers()));
        obj.put("responseData", responseData);
        return obj;
    }

    private JSONObject createHeadersObject(HttpHeaders headers) {
        JSONObject obj = new JSONObject(true);
        for (Iterator<Map.Entry<String, String>> iterator = headers.iteratorAsString(); iterator.hasNext(); ) {
            Map.Entry<String, String> entry = iterator.next();
            String name = entry.getKey();
            if ("x-netguard-session".equalsIgnoreCase(name) ||
                    "x-netguard-fake-response".equalsIgnoreCase(name) ||
                    "x-http2-stream-id".equalsIgnoreCase(name) ||
                    "x-http2-stream-weight".equalsIgnoreCase(name)) {
                continue;
            }
            obj.put(name, entry.getValue());
        }
        return obj;
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
    public CancelResult cancelRequest(HttpRequest request, byte[] requestData, boolean polling) {
        return null;
    }

    @Override
    public boolean filterHost(String hostName) {
        return true;
    }

    protected final byte[] decodeContent(String contentEncoding, byte[] data) {
        if (contentEncoding == null) {
            return data;
        }
        try {
            switch (contentEncoding) {
                case "deflate": {
                    return ZipUtil.unZlib(data);
                }
                case "gzip": {
                    return ZipUtil.unGzip(data);
                }
                case "br": {
                    try (InputStream inputStream = new BrotliCompressorInputStream(new ByteArrayInputStream(data))) {
                        return IoUtil.readBytes(inputStream);
                    }
                }
                default:
                    throw new UnsupportedOperationException("contentEncoding=" + contentEncoding);
            }
        } catch (IOException | IORuntimeException e) {
            log.debug("decodeContent failed: contentEncoding={}", contentEncoding, e);
            return data;
        }
    }

}

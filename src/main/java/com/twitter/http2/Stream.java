package com.twitter.http2;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;

import java.io.ByteArrayOutputStream;

class Stream {

    final HttpHeadersFrame httpHeadersFrame;
    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    Stream(HttpHeadersFrame httpHeadersFrame) {
        this.httpHeadersFrame = httpHeadersFrame;
    }

    boolean longPolling;
    boolean headerWritten;

    final boolean detectLongPolling() {
        HttpHeaders headers = httpHeadersFrame.headers();
        return !headers.contains(HttpHeaderNames.CONTENT_LENGTH) &&
                !headers.contains(HttpHeaderNames.TRANSFER_ENCODING) &&
                !headers.contains(HttpHeaderNames.CONTENT_RANGE);
    }

    @Override
    public String toString() {
        return "Stream{" +
                "httpHeadersFrame=" + httpHeadersFrame +
                ", longPolling=" + longPolling +
                '}';
    }
}

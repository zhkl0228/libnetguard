package com.twitter.http2;

import java.io.ByteArrayOutputStream;

class Stream {

    final HttpHeadersFrame httpHeadersFrame;
    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    Stream(HttpHeadersFrame httpHeadersFrame) {
        this.httpHeadersFrame = httpHeadersFrame;
    }

    boolean longPolling;

}

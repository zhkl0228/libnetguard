package com.twitter.http2;

import java.io.ByteArrayOutputStream;

class Stream {

    final HttpHeadersFrame httpHeadersFrame;
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();

    Stream(HttpHeadersFrame httpHeadersFrame) {
        this.httpHeadersFrame = httpHeadersFrame;
    }

}

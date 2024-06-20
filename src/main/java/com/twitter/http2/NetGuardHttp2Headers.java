package com.twitter.http2;

import io.netty.handler.codec.http.DefaultHttpHeaders;

public class NetGuardHttp2Headers extends DefaultHttpHeaders {

    public NetGuardHttp2Headers() {
        super(false);
    }
}

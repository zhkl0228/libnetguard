package com.twitter.http2;

import io.netty.handler.codec.http.DefaultHttpHeaders;

class NetGuardHttp2Headers extends DefaultHttpHeaders {

    NetGuardHttp2Headers() {
        super(false);
    }
}

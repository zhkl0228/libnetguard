package com.twitter.http2;

import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpHeadersFactory;

public class NetGuardHttp2Headers extends DefaultHttpHeaders {

    public NetGuardHttp2Headers() {
        super(DefaultHttpHeadersFactory.headersFactory().withNameValidation(false).getNameValidator(),
                DefaultHttpHeadersFactory.headersFactory().withValidation(false).getValueValidator());
    }
}

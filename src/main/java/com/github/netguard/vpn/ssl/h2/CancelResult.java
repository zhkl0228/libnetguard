package com.github.netguard.vpn.ssl.h2;

import io.netty.handler.codec.http.HttpResponse;

public class CancelResult {

    private static final CancelResult CANCEL_RESULT = new CancelResult(true, null, null);

    public static CancelResult cancel() {
        return CANCEL_RESULT;
    }

    public static CancelResult fake(HttpResponse response, byte[] responseData) {
        if (response == null) {
            throw new NullPointerException();
        }
        return new CancelResult(false, response, responseData);
    }

    public final boolean cancel;
    public final HttpResponse response;
    public final byte[] responseData;

    private CancelResult(boolean cancel, HttpResponse response, byte[] responseData) {
        this.cancel = cancel;
        this.response = response;
        this.responseData = responseData;
    }

}

package com.github.netguard.handler.session;

@SuppressWarnings("unused")
public class DecodeFailedException extends Exception {

    public DecodeFailedException(String message) {
        super(message);
    }

    public DecodeFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public DecodeFailedException(Throwable cause) {
        super(cause);
    }

    public DecodeFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}

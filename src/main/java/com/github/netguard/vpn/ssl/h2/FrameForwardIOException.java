package com.github.netguard.vpn.ssl.h2;

import java.io.IOException;

public class FrameForwardIOException extends RuntimeException {

    private final IOException target;

    public FrameForwardIOException(IOException target) {
        this.target = target;
    }

    public IOException getTarget() {
        return target;
    }

}

package com.github.netguard.vpn.udp;

import tech.kwik.core.frame.QuicFrame;

import java.nio.BufferUnderflowException;
import java.util.List;

class ReassembleException extends BufferUnderflowException {

    final List<QuicFrame> frameList;

    ReassembleException(List<QuicFrame> frameList) {
        this.frameList = frameList;
    }

}

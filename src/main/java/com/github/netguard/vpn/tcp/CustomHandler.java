package com.github.netguard.vpn.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface CustomHandler {

    void handle(InputStream clientInput, OutputStream clientOutput) throws IOException;

}

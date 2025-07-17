package com.github.netguard.vpn.tcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

class PrologueInputStream extends InputStream {

    private final ByteArrayInputStream bais;
    private final DataInputStream dataInput;
    private final ByteArrayOutputStream baos;

    PrologueInputStream(ByteArrayOutputStream baos, DataInputStream dataInput) {
        this.bais = new ByteArrayInputStream(baos.toByteArray());
        this.dataInput = dataInput;
        this.baos = baos;
    }

    @Override
    public int read() throws IOException {
        if(bais.available() > 0) {
            return bais.read();
        }
        int b = dataInput.read();
        if(b == -1) {
            throw new EOFException();
        }
        baos.write(b);
        return b;
    }

}

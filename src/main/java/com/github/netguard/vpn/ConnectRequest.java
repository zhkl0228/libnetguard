package com.github.netguard.vpn;

import com.github.netguard.vpn.tls.TlsSignature;
import eu.faircode.netguard.Application;

public interface ConnectRequest<T> {

    ClientOS getClientOS();
    Application[] queryApplications();
    TlsSignature getTlsSignature();
    byte[] getPrologue();
    String getExtraData();

    T disconnect();

    T readMorePrologue(int needPrologueCount);

}

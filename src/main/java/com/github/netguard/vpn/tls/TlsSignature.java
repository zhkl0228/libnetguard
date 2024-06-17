package com.github.netguard.vpn.tls;

public interface TlsSignature {

    String getJa3Text();
    String getJa3nText();

    String getJa4Text();

    String getPeetPrintText();

}

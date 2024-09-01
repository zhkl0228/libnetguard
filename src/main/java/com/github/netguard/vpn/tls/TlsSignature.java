package com.github.netguard.vpn.tls;

public interface TlsSignature {

    /**
     * <a href="https://tls.browserleaks.com/json">API</a>
     */
    String getJa3Text();
    String getJa3nText();

    /**
     * <a href="https://tls.browserscan.net/api/tls">API</a>
     */
    String getJa4Text();

    /**
     * <a href="https://tls.peet.ws/api/all">API</a>
     */
    String getPeetPrintText();

    /**
     * <a href="https://scrapfly.io/web-scraping-tools/ja3-fingerprint">Scrapfly FP</a>
     * <a href="https://tools.scrapfly.io/api/fp/ja3">API</a>
     */
    String getScrapflyFP();

}

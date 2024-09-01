package com.github.netguard.vpn.tls;

import java.util.List;
import java.util.Map;

public interface ClientHello {

    int getClientVersion();
    String getHostName();
    List<Integer> getCipherSuites();
    Map<Integer, byte[]> getExtensionTypes();
    List<String> getApplicationLayerProtocols();
    List<Integer> getSignatureAlgorithms();
    List<Integer> getEllipticCurves();
    List<Integer> getEllipticCurvePointFormats();

    char getJa4Prefix();

    List<Integer> getCompressionMethods();

}

package com.github.netguard.vpn.ssl;

interface ServerCertificateNotifier {

    void handshakeCompleted(ServerCertificate serverCertificate);

}

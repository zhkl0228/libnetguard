package com.github.netguard.vpn.ssl;

import org.bouncycastle.operator.OperatorCreationException;
import org.littleshoot.proxy.mitm.Authority;
import org.littleshoot.proxy.mitm.CertificateHelper;
import org.littleshoot.proxy.mitm.SubjectAlternativeNameHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ServerCertificate {

    private static final Logger log = LoggerFactory.getLogger(ServerCertificate.class);

    private static final Map<String, SSLContext> proxyCertMap = new ConcurrentHashMap<>();
    private static final Map<InetSocketAddress, SSLContext> serverSSLContextMap = new ConcurrentHashMap<>();

    private final X509Certificate peerCertificate;

    public ServerCertificate(X509Certificate peerCertificate) {
        this.peerCertificate = peerCertificate;
    }

    public static SSLContext getSSLContext(InetSocketAddress serverAddress) {
        return serverSSLContextMap.get(serverAddress);
    }

    public void createSSLContext(X509Certificate rootCert, PrivateKey privateKey, InetSocketAddress serverAddress) throws Exception {
        String commonName = getCommonName(peerCertificate);
        SSLContext serverContext = proxyCertMap.get(commonName);
        if (serverContext == null) {
            log.debug("createSSLContext serverAddress={}, peerCertificate={}", serverAddress, peerCertificate);
            SubjectAlternativeNameHolder subjectAlternativeNames = new SubjectAlternativeNameHolder();
            subjectAlternativeNames.addAll(peerCertificate.getSubjectAlternativeNames());
            log.debug("Subject Alternative Names: {}", subjectAlternativeNames);
            serverContext = this.generateServerContext(commonName, subjectAlternativeNames, rootCert, privateKey);
            proxyCertMap.put(commonName, serverContext);
        }
        serverSSLContextMap.put(serverAddress, serverContext);
    }

    private String getCommonName(X509Certificate c) {
        log.debug("Subject DN principal name: {}", c.getSubjectDN().getName());
        for (String each : c.getSubjectDN().getName().split(",\\s*")) {
            if (each.startsWith("CN=")) {
                String result = each.substring(3);
                log.debug("Common Name: {}", result);
                return result;
            }
        }
        throw new IllegalStateException("Missed CN in Subject DN: " + c.getSubjectDN());
    }

    private SSLContext generateServerContext(String commonName, SubjectAlternativeNameHolder subjectAlternativeNames, X509Certificate rootCert, PrivateKey privateKey) throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyManagementException, SignatureException, KeyStoreException, InvalidKeyException, UnrecoverableKeyException {
        String alias = "tcpcap";
        Authority authority = new Authority(null, alias, alias.toCharArray(), "TCPcap Proxy SSL Proxying", "XML", "XML Ltd", "XML", "XML Ltd");
        KeyStore ks = CertificateHelper.createServerCertificate(commonName,
                subjectAlternativeNames, authority, rootCert, privateKey);
        if (log.isDebugEnabled()) {
            log.debug("generateServerContext: {}", ks.getCertificate(alias));
        }
        KeyManager[] keyManagers = CertificateHelper.getKeyManagers(ks, authority);
        return CertificateHelper.newServerContext(keyManagers);
    }

}

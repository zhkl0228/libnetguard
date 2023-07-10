package com.github.netguard.vpn.ssl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

class ServerCertificate {

    private static final Logger log = LoggerFactory.getLogger(ServerCertificate.class);

    private static final Map<String, SSLContext> proxyCertMap = new ConcurrentHashMap<>();

    private final X509Certificate peerCertificate;

    public ServerCertificate(X509Certificate peerCertificate) {
        this.peerCertificate = peerCertificate;
    }

    SSLContext createSSLContext(RootCert rootCert) throws Exception {
        String commonName = getCommonName(peerCertificate);
        SSLContext serverContext = proxyCertMap.get(commonName);
        if (serverContext == null) {
            SubjectAlternativeNameHolder subjectAlternativeNames = new SubjectAlternativeNameHolder();
            subjectAlternativeNames.addAll(peerCertificate.getSubjectAlternativeNames());
            log.debug("Subject Alternative Names: {}", subjectAlternativeNames);
            serverContext = this.generateServerContext(commonName, subjectAlternativeNames, rootCert);
            proxyCertMap.put(commonName, serverContext);
        }
        return serverContext;
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

    private SSLContext generateServerContext(String commonName, SubjectAlternativeNameHolder subjectAlternativeNames, RootCert rootCert) throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyManagementException, SignatureException, KeyStoreException, InvalidKeyException, UnrecoverableKeyException {
        String alias = "tcpcap";
        Authority authority = new Authority(null, alias, alias.toCharArray(), "TCPcap Proxy SSL Proxying", "MTX", "MTX Ltd", "MTX", "MTX Ltd");
        KeyStore ks = createServerCertificate(commonName,
                subjectAlternativeNames, authority, rootCert.rootCert, rootCert.privateKey, peerCertificate);
        if (log.isTraceEnabled()) {
            log.trace("generateServerContext: {}", ks.getCertificate(alias));
        }
        KeyManager[] keyManagers = getKeyManagers(ks, authority);
        return newServerContext(keyManagers);
    }

    private static KeyManager[] getKeyManagers(KeyStore keyStore,
                                              Authority authority) throws NoSuchAlgorithmException,
            UnrecoverableKeyException,
            KeyStoreException {
        String keyManAlg = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManAlg
                /* , PROVIDER_NAME */);
        kmf.init(keyStore, authority.password());
        return kmf.getKeyManagers();
    }

    private static SSLContext newServerContext(KeyManager[] keyManagers)
            throws NoSuchAlgorithmException,
            KeyManagementException {
        SSLContext result = newSSLContext();
        SecureRandom random = new SecureRandom();
        random.setSeed(System.currentTimeMillis());
        result.init(keyManagers, null, random);
        return result;
    }

    /**
     * Enforce TLS 1.2 if available, since it's not default up to Java 8.
     * <p>
     * Java 7 disables TLS 1.1 and 1.2 for clients. From <a href=
     * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html"
     * >Java Cryptography Architecture Oracle Providers Documentation:</a>
     * Although SunJSSE in the Java SE 7 release supports TLS 1.1 and TLS 1.2,
     * neither version is enabled by default for client connections. Some
     * servers do not implement forward compatibility correctly and refuse to
     * talk to TLS 1.1 or TLS 1.2 clients. For interoperability, SunJSSE does
     * not enable TLS 1.1 or TLS 1.2 by default for client connections.
     */
    private static final String SSL_CONTEXT_PROTOCOL = "TLSv1.2";
    /**
     * {@link SSLContext}: Every implementation of the Java platform is required
     * to support the following standard SSLContext protocol: TLSv1
     */
    private static final String SSL_CONTEXT_FALLBACK_PROTOCOL = "TLSv1";

    public static SSLContext newSSLContext() throws NoSuchAlgorithmException {
        try {
            log.debug("Using protocol {}", SSL_CONTEXT_PROTOCOL);
            return SSLContext.getInstance(SSL_CONTEXT_PROTOCOL
                    /* , PROVIDER_NAME */);
        } catch (NoSuchAlgorithmException e) {
            log.warn("Protocol {} not available, falling back to {}", SSL_CONTEXT_PROTOCOL,
                    SSL_CONTEXT_FALLBACK_PROTOCOL);
            return SSLContext.getInstance(SSL_CONTEXT_FALLBACK_PROTOCOL
                    /* , PROVIDER_NAME */);
        }
    }

    private static final int FAKE_KEYSIZE = 2048;

    private static KeyStore createServerCertificate(String commonName,
                                                    SubjectAlternativeNameHolder subjectAlternativeNames,
                                                    Authority authority, X509Certificate caCert, PrivateKey caPrivateKey, X509Certificate peerCertificate)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            IOException, OperatorCreationException, CertificateException,
            InvalidKeyException, SignatureException, KeyStoreException {

        KeyPair keyPair = generateKeyPair();

        X500Name issuer = new X509CertificateHolder(caCert.getEncoded())
                .getSubject();
        BigInteger serial = BigInteger.valueOf(initRandomSerial());

        X500NameBuilder name = new X500NameBuilder(BCStyle.INSTANCE);
        name.addRDN(BCStyle.CN, commonName);
        name.addRDN(BCStyle.O, authority.certOrganisation());
        name.addRDN(BCStyle.OU, authority.certOrganizationalUnitName());
        X500Name subject = name.build();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, peerCertificate.getNotBefore(), peerCertificate.getNotAfter(), subject,
                keyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(false));

        subjectAlternativeNames.fillInto(builder);

        X509Certificate cert = signCertificate(builder, caPrivateKey);

        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        KeyStore result = KeyStore.getInstance(KeyStore.getDefaultType()
                /* , PROVIDER_NAME */);
        result.load(null, null);
        Certificate[] chain = { cert, caCert };
        result.setKeyEntry(authority.alias(), keyPair.getPrivate(),
                authority.password(), chain);

        return result;
    }

    @SuppressWarnings("deprecation")
    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key)
            throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(key.getEncoded());
        try (ASN1InputStream is = new ASN1InputStream(bIn)) {
            ASN1Sequence seq = (ASN1Sequence) is.readObject();
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
        }
    }

    private static X509Certificate signCertificate(
            X509v3CertificateBuilder certificateBuilder,
            PrivateKey signedWithPrivateKey) throws OperatorCreationException,
            CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(
                PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }

    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    private static final String SIGNATURE_ALGORITHM = "SHA512WithRSAEncryption";

    private static final String KEYGEN_ALGORITHM = "RSA";

    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    private static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance(KEYGEN_ALGORITHM/* , PROVIDER_NAME */);
        SecureRandom secureRandom = SecureRandom
                .getInstance(SECURE_RANDOM_ALGORITHM/* , PROVIDER_NAME */);
        generator.initialize(ServerCertificate.FAKE_KEYSIZE, secureRandom);
        return generator.generateKeyPair();
    }

    public static long initRandomSerial() {
        final Random rnd = new Random();
        rnd.setSeed(System.currentTimeMillis());
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        long random = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xffffffffL);
        // let reserve of 16 bit for increasing, serials have to be positive
        random = random & 0x0000ffffffffffffL;
        return random;
    }

}

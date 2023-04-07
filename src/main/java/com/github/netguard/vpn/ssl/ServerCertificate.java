package com.github.netguard.vpn.ssl;

import org.apache.commons.io.IOUtils;
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
import org.littleshoot.proxy.mitm.Authority;
import org.littleshoot.proxy.mitm.CertificateHelper;
import org.littleshoot.proxy.mitm.SubjectAlternativeNameHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
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
import java.security.Security;
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

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

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
                subjectAlternativeNames, authority, rootCert.rootCert, rootCert.privateKey);
        if (log.isTraceEnabled()) {
            log.trace("generateServerContext: {}", ks.getCertificate(alias));
        }
        KeyManager[] keyManagers = CertificateHelper.getKeyManagers(ks, authority);
        return CertificateHelper.newServerContext(keyManagers);
    }

    private static final int FAKE_KEYSIZE = 2048;

    private static KeyStore createServerCertificate(String commonName,
                                                   SubjectAlternativeNameHolder subjectAlternativeNames,
                                                   Authority authority, Certificate caCert, PrivateKey caPrivKey)
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
                issuer, serial, NOT_BEFORE, NOT_AFTER, subject,
                keyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(false));

        subjectAlternativeNames.fillInto(builder);

        X509Certificate cert = signCertificate(builder, caPrivKey);

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
        ASN1InputStream is = null;
        try {
            is = new ASN1InputStream(bIn);
            ASN1Sequence seq = (ASN1Sequence) is.readObject();
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
        } finally {
            IOUtils.closeQuietly(is);
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

    /**
     * Current time minus 1 year, just in case software clock goes back due to
     * time synchronization
     */
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365);

    /**
     * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
     * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
     * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
     * Hundred years in the future from starting the proxy should be enough.
     */
    private static final Date NOT_AFTER = new Date(
            System.currentTimeMillis() + 86400000L * 365);

    private static final String KEYGEN_ALGORITHM = "RSA";

    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    private static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException {
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
        long sl = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xFFFFFFFFL);
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl & 0x0000FFFFFFFFFFFFL;
        return sl;
    }

}

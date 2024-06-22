package com.github.netguard.vpn.tcp;

import net.luminis.tls.handshake.TlsServerEngineFactory;
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
import java.security.InvalidAlgorithmParameterException;
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
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

public class ServerCertificate {

    private static final Logger log = LoggerFactory.getLogger(ServerCertificate.class);

    private static final Map<String, ServerContext> proxyCertMap = new ConcurrentHashMap<>();

    private final X509Certificate peerCertificate;

    public ServerCertificate(X509Certificate peerCertificate) {
        this.peerCertificate = peerCertificate;
    }

    public ServerContext getServerContext(RootCert rootCert) throws Exception {
        String commonName = getCommonName(peerCertificate);
        ServerContext serverContext = proxyCertMap.get(commonName);
        if (serverContext == null) {
            SubjectAlternativeNameHolder subjectAlternativeNames = new SubjectAlternativeNameHolder();
            subjectAlternativeNames.addAll(peerCertificate.getSubjectAlternativeNames());
            log.debug("createSSLContext Subject Alternative Names: {}", subjectAlternativeNames);
            serverContext = this.generateServerContext(commonName, subjectAlternativeNames, rootCert);
            proxyCertMap.put(commonName, serverContext);
        }
        return serverContext;
    }

    private String getCommonName(X509Certificate certificate) {
        log.debug("Subject DN principal name: {}", certificate.getSubjectDN().getName());
        for (String each : certificate.getSubjectDN().getName().split(",\\s*")) {
            if (each.startsWith("CN=")) {
                String result = each.substring(3);
                log.debug("Common Name: {}", result);
                return result;
            }
        }
        throw new IllegalStateException("Missed CN in Subject DN: " + certificate.getSubjectDN());
    }

    public static class ServerContext {
        final Authority authority;
        final KeyStore keyStore;
        ServerContext(Authority authority, KeyStore keyStore) {
            this.authority = authority;
            this.keyStore = keyStore;
        }
        public SSLContext newSSLContext() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
            KeyManager[] keyManagers = getKeyManagers(keyStore, authority);
            return newServerContext(keyManagers);
        }
        public TlsServerEngineFactory newTlsServerEngineFactory() throws CertificateException, IOException, InvalidKeySpecException {
            return new TlsServerEngineFactory(keyStore, authority.alias(), authority.password());
        }
    }

    private ServerContext generateServerContext(String commonName, SubjectAlternativeNameHolder subjectAlternativeNames, RootCert rootCert) throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException {
        String alias = "tcpcap";
        Authority authority = new Authority(null, alias, alias.toCharArray(), "TCPcap Proxy SSL Proxying", "MTX", "MTX Ltd", "MTX", "MTX Ltd");
        KeyStore keyStore = createServerCertificate(commonName,
                subjectAlternativeNames, authority, rootCert.rootCert, rootCert.privateKey, peerCertificate);
        if (log.isTraceEnabled()) {
            log.trace("generateServerContext: {}", keyStore.getCertificate(alias));
        }
        return new ServerContext(authority, keyStore);
    }

    private static KeyManager[] getKeyManagers(KeyStore keyStore,
                                              Authority authority) throws NoSuchAlgorithmException,
            UnrecoverableKeyException,
            KeyStoreException {
        String keyManAlg = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManAlg);
        kmf.init(keyStore, authority.password());
        return kmf.getKeyManagers();
    }

    private static SSLContext newServerContext(KeyManager[] keyManagers)
            throws KeyManagementException {
        SSLContext result = newSSLContext();
        result.init(keyManagers, null, null);
        return result;
    }

    public static SSLContext newSSLContext() {
        try {
            return SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Protocol not available", e);
        }
    }

    private static KeyStore createServerCertificate(String commonName,
                                                    SubjectAlternativeNameHolder subjectAlternativeNames,
                                                    Authority authority, X509Certificate caCert, PrivateKey caPrivateKey, X509Certificate peerCertificate)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            IOException, OperatorCreationException, CertificateException,
            InvalidKeyException, SignatureException, KeyStoreException, InvalidAlgorithmParameterException {
        String algorithm = peerCertificate.getPublicKey().getAlgorithm();
        log.debug("createServerCertificate algorithm={}, commonName={}, authority={}, peerCertificate={}", algorithm, commonName, authority, peerCertificate);
        KeyPair keyPair = generateKeyPair(algorithm);

        X500Name issuer = new X509CertificateHolder(caCert.getEncoded()).getSubject();
        BigInteger serial = BigInteger.valueOf(initRandomSerial());

        X500NameBuilder name = new X500NameBuilder(BCStyle.INSTANCE);
        name.addRDN(BCStyle.CN, commonName);
        name.addRDN(BCStyle.O, authority.certOrganisation());
        name.addRDN(BCStyle.OU, authority.certOrganizationalUnitName());
        X500Name subject = name.build();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, peerCertificate.getNotBefore(), peerCertificate.getNotAfter(), subject,
                keyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        subjectAlternativeNames.fillInto(builder);

        X509Certificate cert = signCertificate(caCert.getSigAlgName(), builder, caPrivateKey);

        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        KeyStore result = KeyStore.getInstance(KeyStore.getDefaultType());
        result.load(null, null);
        Certificate[] chain = { cert, caCert };
        result.setKeyEntry(authority.alias(), keyPair.getPrivate(), authority.password(), chain);

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
            String signatureAlgorithm,
            X509v3CertificateBuilder builder,
            PrivateKey signedWithPrivateKey) throws OperatorCreationException,
            CertificateException {
        log.debug("signCertificate signatureAlgorithm={}, signedWithPrivateKey={}", signatureAlgorithm, signedWithPrivateKey);
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    private static KeyPair generateKeyPair(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, PROVIDER_NAME);
        switch (algorithm) {
            case "EC":
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                break;
            case "RSA":
                generator.initialize(2048);
                break;
            default:
                throw new UnsupportedOperationException("algorithm=" + algorithm);
        }
        return generator.generateKeyPair();
    }

    public static long initRandomSerial() {
        Random rnd = new Random();
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        long random = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xffffffffL);
        // let reserve of 16 bit for increasing, serials have to be positive
        random = random & 0x0000ffffffffffffL;
        return random;
    }

}

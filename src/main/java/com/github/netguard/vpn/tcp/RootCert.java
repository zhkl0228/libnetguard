package com.github.netguard.vpn.tcp;

import eu.faircode.netguard.ServiceSinkhole;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class RootCert {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    final X509Certificate rootCert;
    final PrivateKey privateKey;
    public final String pem;

    private RootCert(X509Certificate rootCert, PrivateKey privateKey, String pem) {
        this.rootCert = rootCert;
        this.privateKey = privateKey;
        this.pem = pem;
    }

    /**
     * Export charles-ssl-proxying.p12 with password "charles": Charles => Help => SSL Proxying => Export Charles Root Certificate and Private Key...
     * keytool -genkeypair -keystore charles-ssl-proxying.p12 -storetype PKCS12 -storepass charles -alias charles -keyalg RSA -keysize 2048 -validity 365 -dname "CN=netguard, OU=MTX Ltd, O=MTX, L=GuangZhou, ST=GuangDong, C=CN" -ext BC:critical=CA:TRUE -ext KU:critical=keyCertSign
     * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html#supported-named-extensions">keytool</a>
     */
    public static RootCert load() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            String alias = "charles";
            try (InputStream inputStream = ServiceSinkhole.class.getResourceAsStream("/charles-ssl-proxying.p12")) {
                keyStore.load(inputStream, alias.toCharArray());
            }
            X509Certificate rootCert = (X509Certificate) keyStore.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

            Object[] certs = keyStore.getCertificateChain(alias);
            StringWriter writer = new StringWriter();
            exportPem(writer, certs);
            return new RootCert(rootCert, privateKey, writer.toString());
        } catch (Exception e) {
            throw new IllegalStateException("load RootCert failed.", e);
        }
    }

    private static void exportPem(Writer writer, Object... certs)
            throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(writer)) {
            for (Object cert : certs) {
                pw.writeObject(cert);
                pw.flush();
            }
        }
    }

}

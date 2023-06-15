package com.github.netguard.vpn.ssl;

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

    public static RootCert load() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
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

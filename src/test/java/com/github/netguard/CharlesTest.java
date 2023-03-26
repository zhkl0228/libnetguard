package com.github.netguard;

import eu.faircode.netguard.ServiceSinkhole;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class CharlesTest extends TestCase {

    public void testPrivateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        String alias = "charles";
        try (InputStream inputStream = ServiceSinkhole.class.getResourceAsStream("/charles-ssl-proxying.p12")) {
            keyStore.load(inputStream, alias.toCharArray());
        }

        {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, alias.toCharArray());

            SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(keyManagerFactory.getKeyManagers(), null, null);
            serverContext.getServerSessionContext().setSessionTimeout(10);
            assertNotNull(serverContext);
        }

        X509Certificate rootCert = (X509Certificate) keyStore.getCertificate(alias);
        assertNotNull(rootCert);
        System.out.println(rootCert);

        {
            String str = Base64.encodeBase64String(rootCert.getEncoded());
            StringBuilder builder = new StringBuilder();
            builder.append("-----BEGIN CERTIFICATE-----\n");
            char[] cs = str.toCharArray();
            for (int i = 0; i < cs.length; i++) {
                builder.append(cs[i]);
                if ((i + 1) % 76 == 0) {
                    builder.append("\n");
                }
            }
            builder.append("\n-----END CERTIFICATE-----\n");
            System.out.println(builder);
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        assertNotNull(privateKey);
        System.out.println(privateKey);
    }

}
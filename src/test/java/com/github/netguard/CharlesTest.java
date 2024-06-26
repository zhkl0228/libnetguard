package com.github.netguard;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ZipUtil;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class CharlesTest extends TestCase {

    public void testPrivateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        String alias = "charles";
        try (InputStream inputStream = CharlesTest.class.getResourceAsStream("/charles-ssl-proxying.p12")) {
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
        assertEquals("SHA256WITHRSA", rootCert.getSigAlgName());
        System.out.println(rootCert);

        {
            byte[] data = rootCert.getEncoded();
            String str = Base64.encode(data);
            System.out.println("CA=" + str + ", length=" + str.length() + ", data.length=" + data.length + ", zlibLength=" + ZipUtil.zlib(str.getBytes(), 9).length + ", gzipLength=" + ZipUtil.gzip(str.getBytes()).length);
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
            System.out.println(builder + "length=" + builder.length());
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        assertNotNull(privateKey);
        System.out.println(privateKey);

        {
            Object[] certs = keyStore.getCertificateChain(alias);
            StringWriter writer = new StringWriter();
            exportPem(writer, certs);
            System.out.println(writer);
            FileUtil.writeString(writer.toString(), new File("target/ca.pem"), StandardCharsets.UTF_8);
        }
    }

    private void exportPem(Writer writer, Object... certs)
            throws IOException {
        JcaPEMWriter pw = null;
        try {
            pw = new JcaPEMWriter(writer);
            for (Object cert : certs) {
                pw.writeObject(cert);
                pw.flush();
            }
        } finally {
            IoUtil.close(pw);
        }
    }

}

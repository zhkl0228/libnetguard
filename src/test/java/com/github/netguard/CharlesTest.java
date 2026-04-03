package com.github.netguard;

import junit.framework.TestCase;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;
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
            String str = Base64.encodeBase64String(data);
            byte[] zlibData;
            {
                Deflater deflater = new Deflater(9);
                deflater.setInput(str.getBytes());
                deflater.finish();
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                while (!deflater.finished()) {
                    bos.write(buf, 0, deflater.deflate(buf));
                }
                deflater.end();
                zlibData = bos.toByteArray();
            }
            byte[] gzipData;
            {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                try (GZIPOutputStream gzip = new GZIPOutputStream(bos)) {
                    gzip.write(str.getBytes());
                }
                gzipData = bos.toByteArray();
            }
            System.out.println("CA=" + str + ", length=" + str.length() + ", data.length=" + data.length + ", zlibLength=" + zlibData.length + ", gzipLength=" + gzipData.length);
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
            FileUtils.write(new File("target/ca.pem"), writer.toString(), StandardCharsets.UTF_8);
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
            IOUtils.closeQuietly(pw);
        }
    }

}

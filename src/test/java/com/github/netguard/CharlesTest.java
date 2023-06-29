package com.github.netguard;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ZipUtil;
import cn.hutool.crypto.digest.DigestUtil;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
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
        System.out.println(rootCert);
        System.out.println("IssuerX500PrincipalHash=" + DigestUtil.md5Hex(rootCert.getIssuerX500Principal().getEncoded()));

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(("-----BEGIN CERTIFICATE-----\n" +
                "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G\n" +
                "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp\n" +
                "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1\n" +
                "MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG\n" +
                "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL\n" +
                "v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8\n" +
                "eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq\n" +
                "tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n" +
                "C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa\n" +
                "zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB\n" +
                "mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH\n" +
                "V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n\n" +
                "bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG\n" +
                "3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs\n" +
                "J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO\n" +
                "291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS\n" +
                "ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n" +
                "AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7\n" +
                "TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n" +
                "-----END CERTIFICATE-----").getBytes())); // 111e6273.0
        System.out.println("certificate=\n" + certificate);
        System.out.println("SubjectX500PrincipalHash=" + DigestUtil.md5Hex(certificate.getSubjectX500Principal().getEncoded()));
        System.out.println("IssuerX500PrincipalHash=" + DigestUtil.md5Hex(certificate.getIssuerX500Principal().getEncoded()));

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

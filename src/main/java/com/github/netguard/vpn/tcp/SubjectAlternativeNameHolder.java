package com.github.netguard.vpn.tcp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

class SubjectAlternativeNameHolder {

    private static final Pattern TAGS_PATTERN = Pattern.compile("["
            + GeneralName.iPAddress + GeneralName.dNSName + "]");

    private final List<ASN1Encodable> sans = new ArrayList<>();

    public void addIpAddress(String ipAddress) {
        sans.add(new GeneralName(GeneralName.iPAddress, ipAddress));
    }

    public void addDomainName(String subjectAlternativeName) {
        sans.add(new GeneralName(GeneralName.dNSName, subjectAlternativeName));
    }

    public void fillInto(X509v3CertificateBuilder certGen)
            throws CertIOException {
        if (!sans.isEmpty()) {
            ASN1Encodable[] encodables = sans.toArray(new ASN1Encodable[0]);
            certGen.addExtension(Extension.subjectAlternativeName, false,
                    new DERSequence(encodables));
        }
    }

    public void addAll(Collection<List<?>> subjectAlternativeNames) {
        if (subjectAlternativeNames != null) {
            for (List<?> each : subjectAlternativeNames) {
                sans.add(parseGeneralName(each));
            }
        }
    }

    private ASN1Encodable parseGeneralName(List<?> nameEntry) {
        if (nameEntry == null || nameEntry.size() != 2) {
            throw new IllegalArgumentException(nameEntry != null ? String.valueOf(nameEntry) : "nameEntry is null");
        }
        String tag = String.valueOf(nameEntry.get(0));
        Matcher m = TAGS_PATTERN.matcher(tag);
        if (m.matches()) {
            return new GeneralName(Integer.parseInt(tag),
                    String.valueOf(nameEntry.get(1)));
        }
        throw new IllegalArgumentException(String.valueOf(nameEntry));
    }
}

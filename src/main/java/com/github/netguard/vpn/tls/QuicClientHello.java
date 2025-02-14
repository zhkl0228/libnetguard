package com.github.netguard.vpn.tls;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.extension.ApplicationLayerProtocolNegotiationExtension;
import tech.kwik.agent15.extension.CertificateAuthoritiesExtension;
import tech.kwik.agent15.extension.ClientHelloPreSharedKeyExtension;
import tech.kwik.agent15.extension.KeyShareExtension;
import tech.kwik.agent15.extension.PskKeyExchangeModesExtension;
import tech.kwik.agent15.extension.ServerNameExtension;
import tech.kwik.agent15.extension.SupportedGroupsExtension;
import tech.kwik.agent15.extension.SupportedVersionsExtension;
import tech.kwik.agent15.extension.UnknownExtension;
import tech.kwik.agent15.extension.EarlyDataExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.SignatureAlgorithmsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class QuicClientHello implements ClientHello {

    private final tech.kwik.agent15.handshake.ClientHello clientHello;
    private final String hostName;
    private final List<String> applicationLayerProtocols;

    public QuicClientHello(tech.kwik.agent15.handshake.ClientHello clientHello, String hostName, List<String> applicationLayerProtocols) {
        this.clientHello = clientHello;
        this.hostName = hostName;
        this.applicationLayerProtocols = Collections.unmodifiableList(applicationLayerProtocols);
    }

    @Override
    public List<Integer> getCompressionMethods() {
        return Collections.singletonList(0);
    }

    @Override
    public int getClientVersion() {
        return 0x303;
    }

    @Override
    public String getHostName() {
        return hostName;
    }

    @Override
    public List<String> getApplicationLayerProtocols() {
        return applicationLayerProtocols;
    }

    @Override
    public List<Integer> getCipherSuites() {
        List<TlsConstants.CipherSuite> list = clientHello.getCipherSuites();
        List<Integer> cipherSuites = new ArrayList<>(list.size());
        for(TlsConstants.CipherSuite cs : list) {
            cipherSuites.add(cs.value & 0xffff);
        }
        return cipherSuites;
    }

    @Override
    public List<Integer> getSignatureAlgorithms() {
        List<Integer> signatureAlgorithms = new ArrayList<>(10);
        for(Extension extension : clientHello.getExtensions()) {
            if (extension instanceof SignatureAlgorithmsExtension) {
                SignatureAlgorithmsExtension sa = (SignatureAlgorithmsExtension) extension;
                for (TlsConstants.SignatureScheme scheme : sa.getSignatureAlgorithms()) {
                    signatureAlgorithms.add(scheme.value & 0xffff);
                }
                break;
            }
        }
        return signatureAlgorithms;
    }

    @Override
    public List<Integer> getEllipticCurves() {
        List<Integer> ellipticCurves = new ArrayList<>(10);
        for(Extension extension : clientHello.getExtensions()) {
            if (extension instanceof SupportedGroupsExtension) {
                SupportedGroupsExtension sg = (SupportedGroupsExtension) extension;
                for (TlsConstants.NamedGroup namedGroup : sg.getNamedGroups()) {
                    ellipticCurves.add(namedGroup.value & 0xffff);
                }
                break;
            }
        }
        return ellipticCurves;
    }

    private void putExtensionTypes(Map<Integer, byte[]> extensionTypes, int type, byte[] bytes) {
        extensionTypes.put(type, Arrays.copyOfRange(bytes, 4, bytes.length));
    }

    @Override
    public Map<Integer, byte[]> getExtensionTypes() {
        Map<Integer, byte[]> extensionTypes = new LinkedHashMap<>(10);
        for(Extension extension : clientHello.getExtensions()) {
            if (extension instanceof UnknownExtension) {
                UnknownExtension unknownExtension = (UnknownExtension) extension;
                putExtensionTypes(extensionTypes, unknownExtension.getType(), unknownExtension.getData());
            } else if (extension instanceof ServerNameExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.server_name.value & 0xffff, extension.getBytes());
            } else if (extension instanceof SupportedGroupsExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.supported_groups.value & 0xffff, extension.getBytes());
            } else if (extension instanceof SignatureAlgorithmsExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.signature_algorithms.value & 0xffff, extension.getBytes());
            } else if (extension instanceof ApplicationLayerProtocolNegotiationExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.application_layer_protocol_negotiation.value & 0xffff, extension.getBytes());
            } else if (extension instanceof ClientHelloPreSharedKeyExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.pre_shared_key.value & 0xffff, extension.getBytes());
            } else if (extension instanceof EarlyDataExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.early_data.value & 0xffff, extension.getBytes());
            } else if (extension instanceof SupportedVersionsExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.supported_versions.value & 0xffff, extension.getBytes());
            } else if (extension instanceof PskKeyExchangeModesExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.psk_key_exchange_modes.value & 0xffff, extension.getBytes());
            } else if (extension instanceof CertificateAuthoritiesExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.certificate_authorities.value & 0xffff, extension.getBytes());
            } else if (extension instanceof KeyShareExtension) {
                putExtensionTypes(extensionTypes, TlsConstants.ExtensionType.key_share.value & 0xffff, extension.getBytes());
            } else {
                throw new UnsupportedOperationException("extension=" + extension.getClass().getName());
            }
        }
        return extensionTypes;
    }

    @Override
    public List<Integer> getEllipticCurvePointFormats() {
        byte[] ellipticCurvePointFormatsData = getEllipticCurvePointFormatsData();
        if (ellipticCurvePointFormatsData == null) {
            return Collections.emptyList();
        }
        ByteBuffer buffer = ByteBuffer.wrap(ellipticCurvePointFormatsData);
        int curveFormatLength = buffer.get(0) & 0xff;
        List<Integer> ecpf = new ArrayList<>(curveFormatLength);
        JA3Signature.convertUInt8ArrayToJa3(buffer, 1, 1 + curveFormatLength, ecpf);
        return ecpf;
    }

    private byte[] getEllipticCurvePointFormatsData() {
        byte[] data = null;
        for(Extension extension : clientHello.getExtensions()) {
            if(extension instanceof UnknownExtension) {
                UnknownExtension unknownExtension = (UnknownExtension) extension;
                if (unknownExtension.getType() == JA3Signature.TYPE_ELLIPTIC_CURVE_POINT_FORMATS) {
                    byte[] bytes = unknownExtension.getData();
                    data = Arrays.copyOfRange(bytes, 4, bytes.length);
                    break;
                }
            }
        }
        return data;
    }

    @Override
    public char getJa4Prefix() {
        return 'u';
    }
}

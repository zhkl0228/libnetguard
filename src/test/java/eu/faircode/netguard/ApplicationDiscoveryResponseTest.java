package eu.faircode.netguard;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Responses captured from inspectorvpnd on iPhone12,8 / iOS 26.0.1 (Dopamine rootless).
 */
public class ApplicationDiscoveryResponseTest {

    /**
     * Safari loading a page: com.apple.WebKit.Networking holds the user space flow on behalf of MobileSafari.
     */
    private static final String SAFARI_VIA_WEBKIT_NETWORKING = "0306000931302e312e31302e31cb4b000d31342e3231352e3137322e333701bb00000524000c4d6f62696c65536166617269006d2f707269766174652f7661722f636f6e7461696e6572732f42756e646c652f4170706c69636174696f6e2f38363745453244372d423039362d344431362d423637452d4630373245354542343244332f4d6f62696c655361666172692e6170702f4d6f62696c65536166617269010016636f6d2e6170706c652e6d6f62696c657361666172690100065361666172690001000632362e302e3101000f383632322e312e32322e31302e31310100000845001b636f6d2e6170706c652e5765624b69742e4e6574776f726b696e67007a2f707269766174652f707265626f6f742f4372797074657865732f4f532f53797374656d2f4c6962726172792f457874656e73696f6e4b69742f457874656e73696f6e732f4e6574776f726b696e67457874656e73696f6e2e61707065782f636f6d2e6170706c652e5765624b69742e4e6574776f726b696e6701001b636f6d2e6170706c652e5765624b69742e4e6574776f726b696e67000100134e6574776f726b696e67457874656e73696f6e0001000f383632322e312e32322e31302e3131";

    /**
     * WeChat's in-app purchase check, made by storekitd, which sits in a framework directory without a bundle of its own.
     */
    private static final String WECHAT_VIA_STOREKITD = "0306000931302e312e31302e31cb52000c3139382e31382e312e31383701bb00000a12000657654368617400612f707269766174652f7661722f636f6e7461696e6572732f42756e646c652f4170706c69636174696f6e2f31444637304145342d394442312d344233372d394536322d3536454642433942383333442f5765436861742e6170702f57654368617401000f636f6d2e74656e63656e742e78696e010006e5beaee4bfa1010006576543686174010006382e302e3738010009382e302e37382e33340100000a16000973746f72656b697464003f2f53797374656d2f4c6962726172792f4672616d65776f726b732f53746f72654b69742e6672616d65776f726b2f537570706f72742f73746f72656b69746400";

    /**
     * curl from Procursus, a plain executable.
     */
    private static final String CURL = "0306000931302e312e31302e31c13a000e3138332e36302e3131382e32313301bb00000ac100046375726c00982f707269766174652f707265626f6f742f4345384335353942463832314443393439453835454345304237373532304333443842373346333138393145423034394239303741304434433132423138424538444643394245394438323246333044353241343244333433323235443838462f646f70616d696e652d6464665946512f70726f6375727375732f7573722f62696e2f6375726c0000";

    private static Packet packet(String daddr, int sport) {
        Packet packet = new Packet();
        packet.protocol = Packet.TCP_PROTOCOL;
        packet.saddr = "10.1.10.1";
        packet.sport = sport;
        packet.daddr = daddr;
        packet.dport = 443;
        return packet;
    }

    private static IOSApplication decodeSingle(String hex, Packet packet) throws Exception {
        ApplicationDiscoveryResponse response = ApplicationDiscoveryResponse.decode(Hex.decodeHex(hex));
        assertEquals(packet.hashCode(), response.hash);
        assertEquals(1, response.applications.length);
        return (IOSApplication) response.applications[0];
    }

    @Test
    public void testSafariViaWebKitNetworking() throws Exception {
        IOSApplication app = decodeSingle(SAFARI_VIA_WEBKIT_NETWORKING, packet("14.215.172.37", 52043));
        assertEquals("com.apple.mobilesafari", app.getPackageName());
        assertEquals("Safari", app.getLabel());
        assertEquals(1316, app.getPid());
        assertEquals("MobileSafari", app.getProcessName());
        assertEquals("/private/var/containers/Bundle/Application/867EE2D7-B096-4D16-B67E-F072E5EB42D3/MobileSafari.app/MobileSafari", app.getExecutablePath());
        assertEquals("com.apple.mobilesafari", app.getBundleIdentifier());
        assertEquals("Safari", app.getBundleDisplayName());
        assertNull(app.getBundleName());
        assertEquals("26.0.1", app.getShortVersionString());
        assertEquals("8622.1.22.10.11", app.getBundleVersion());

        IOSApplication delegate = app.getDelegate();
        assertEquals("com.apple.WebKit.Networking", delegate.getPackageName());
        assertEquals("NetworkingExtension", delegate.getLabel());
        assertEquals(2117, delegate.getPid());
        assertEquals("/private/preboot/Cryptexes/OS/System/Library/ExtensionKit/Extensions/NetworkingExtension.appex/com.apple.WebKit.Networking", delegate.getExecutablePath());
        assertNull(delegate.getBundleDisplayName());
        assertNull(delegate.getShortVersionString());
        assertNull(delegate.getDelegate());
        assertEquals("Safari(com.apple.mobilesafari, pid=1316) via NetworkingExtension(com.apple.WebKit.Networking, pid=2117)", app.toString());
    }

    @Test
    public void testWeChatViaStorekitd() throws Exception {
        IOSApplication app = decodeSingle(WECHAT_VIA_STOREKITD, packet("198.18.1.187", 52050));
        assertEquals("com.tencent.xin", app.getPackageName());
        assertEquals("微信", app.getLabel());
        assertEquals("WeChat", app.getBundleName());
        assertEquals("8.0.78", app.getShortVersionString());
        assertEquals("8.0.78.34", app.getBundleVersion());

        IOSApplication delegate = app.getDelegate();
        assertEquals("storekitd", delegate.getPackageName());
        assertEquals("storekitd", delegate.getLabel());
        assertEquals(2582, delegate.getPid());
        assertEquals("/System/Library/Frameworks/StoreKit.framework/Support/storekitd", delegate.getExecutablePath());
        assertNull(delegate.getBundleIdentifier());
    }

    @Test
    public void testPlainExecutable() throws Exception {
        IOSApplication app = decodeSingle(CURL, packet("183.60.118.213", 49466));
        assertEquals("curl", app.getPackageName());
        assertEquals("curl", app.getLabel());
        assertEquals(2753, app.getPid());
        assertNull(app.getBundleIdentifier());
        assertNull(app.getDelegate());
        assertEquals(2753, app.getVersionCode());
    }

    @Test
    public void testTrailingBytes() throws Exception {
        byte[] data = Hex.decodeHex(CURL);
        byte[] longer = Arrays.copyOf(data, data.length + 1);
        IOException e = assertThrows(IOException.class, () -> ApplicationDiscoveryResponse.decode(longer));
        assertEquals("1 trailing bytes after application discovery response type 0x3", e.getMessage());
    }

    @Test
    public void testInvalidFlag() throws Exception {
        byte[] data = Hex.decodeHex(CURL);
        data[data.length - 2] = 2; // bundle flag of the owner
        IOException e = assertThrows(IOException.class, () -> ApplicationDiscoveryResponse.decode(data));
        assertEquals("Flag bundle should be 0 or 1: 2", e.getMessage());
    }
}

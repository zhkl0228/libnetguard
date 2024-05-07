package com.github.netguard;

import cn.hutool.core.net.DefaultTrustManager;
import cn.hutool.core.util.HexUtil;
import com.github.netguard.vpn.ssl.ClientHelloRecord;
import com.github.netguard.vpn.ssl.ExtensionServerName;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import junit.framework.TestCase;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.wildfly.openssl.OpenSSLProvider;
import org.wildfly.openssl.SSL;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.security.Security;

public class SSLTest extends TestCase {

    public void testByteBuf() throws Exception {
        ByteBuf byteBuf = Unpooled.buffer();
        assertNotNull(byteBuf);
        System.out.println(byteBuf);
        byteBuf.release();
        System.out.println(byteBuf);

        System.setProperty(SSL.ORG_WILDFLY_OPENSSL_PATH, "/opt/local/lib");
        System.setProperty(SSL.ORG_WILDFLY_LIBWFSSL_PATH, new File(FileUtils.getUserDirectory(),
                "git/wildfly-openssl-natives/macosx-aarch64/target/classes/macosx-aarch64/libwfssl.dylib").getAbsolutePath());
        Security.addProvider(new BouncyCastleJsseProvider(true));
        Security.addProvider(new OpenSSLProvider());
        SSLContext context = SSLContext.getInstance("openssl.TLS");
        assertNotNull(context);
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
    }

    public void testClientHello() throws Exception {
        byte[] data = HexUtil.decodeHex("1603010200010001fc03036515a86f0098c69695c6b21fac8cf4885b1bf516347b5a99b35ece3f21eabde9206098cc5cf04eb4503a5310c8f744f8baacc38a79d14c55d688d68d43a772f7ae0036aaaa130113021303c02cc02bcca9c030c02fcca8c024c023c00ac009c028c027c014c013009d009c003d003c0035002fc008c012000a0100017d3a3a00000000001b0019000016636f75726965722e707573682e6170706c652e636f6d00170000ff01000100000a000c000acaca001d001700180019000b0002010000100020001e1061706e732d73656375726974792d76330c61706e732d7061636b2d7631000500050100000000000d0018001604030804040105030203080508050501080606010201001200000033002b0029caca000100001d00200e201d76f1973f1afd242a18868c606fe1736fe2da38588c52ceaf4699e6720c002d00020101002b000706baba03040303eaea000100001500a5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        ClientHelloRecord clientHelloRecord = ExtensionServerName.parseServerNames(new DataInputStream(new ByteArrayInputStream(data)), null);
        assertNotNull(clientHelloRecord);

        data = HexUtil.decodeHex("504f5354202f5f73746f726520485454502f312e310d0a486f73743a206a702d636f6c2d7463702e6e656c6f2e6c696e65636f72702e636f6d0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a5472616e736665722d456e636f64696e673a204368756e6b65640d0a4163636570743a206170706c69636174696f6e2f6a736f6e0d0a436f6e74656e742d456e636f64696e673a20677a69700d0a557365722d4167656e743a204e656c6f53444b0d0a4163636570742d4c616e67756167653a20656e2d75730d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174652c2062720d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a3244330d0a");
        Inspector.inspect(data, "handleTx");

        data = HexUtil.decodeHex("1f8b08000000000000139c54cb6edb3814ddcf57105e2541248b0f3de8d5d896821ae33c10bbeda22e060c7515b1954957a49c1683f9f75292d304681683d1428f7b78ce3dbc97579ffe99fcd935e671554ed00c4d4a4264063c868c609c6160401259498efdab84ea6172f9074213bf7e63ba56c2c051c6063e3242778d709569f72372bb419885648472382a09d7a6846644ef6aa301d34b3ce237d09895b64e34cd2a1f56a4385bd205cb8334a23c600b9c07f338c1014f58314f59c258968d5c0bbadcaafd6008271989d288259c45f180d6c6ba411073127a38c4617222baef6e6bbe821ee00c579c530a5430ca0416a24a4515f18c534ed3aa8c46cada48d18c5b2ff463a36c8dce96b5d202ed85d28dd0e5f9af32fde62989f0e8e9d09a2f20dd0768ad32637a4cc3388c5eb83f0e6316ed0b435e4afc60ca1f431cdad6b433747a5c5c5ca0b994a6d36edeb91ab4535238af5df4780feff45a69e8c17bf8b6351b5fb3a105774a2f7d57eec11e8cb6805a90a08e50a227e5ea513edc69e4afdab9c3c609d7d99e3043248a464078d1e2bb84439f70c4fa3cdbba55951b0cf4c1b0eef642fb2dabeae4cd1be954eb539db5e2e983683a4f8ccfdfd0bc066bc5a347dff512e8f84ac3fb3d89283d38b4b3dd74377d0a1bbfdb700fbba905b99b1ee96eea77260e4ed6e212b9beeb33d458e9fe16d2df94560e715af956731ed02a8902167316f0f40182384b13e1c9a580f20d771fe161212cbcbf5fcffeab83b755b6ffdbd57836e0b9d4c30159e9cabcccd626ff6b88de14eb5bd48fa60f201cd2f0347f1b5f62efe2347b3867458c4916a469e1732ee779c0894fbc9c932c2f08e319a5af72f643e19e0f72df10b0eef72376f6ba6fd7e06a53ce06fa3b3f350db433db49e96d3c7f9ea33382e397715ac3f1f4f358dd5cddbefead9c5c13b6c819c734487134f7ae090b16694c7cb9e262995d2d697cc59f2be29e4cfbf5d7907d54c1959afcfbf927000000ffff");
        Inspector.inspect(data, "handleTx");
    }

}

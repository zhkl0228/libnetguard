package com.github.netguard;

import cn.hutool.core.util.HexUtil;
import com.twitter.hpack.Decoder;
import com.twitter.hpack.HeaderListener;
import com.twitter.hpack.NetGuardEncoder;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Http2Test extends TestCase {

    public void testDecodeHeaders() throws Exception {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = HexUtil.decodeHex("828704d5636b5fe752fa8197800211f689281b1372c72bb2c6e95f288056592be3f8ee5b1063d500595db5c1f09f5596036b9cf5162d5bbe126a4b005c784e01f6da6977da001f6be2c2cc63d4882f695af69f820ecb0c5b2041909bc795e835455ea1f72d8bf4aee34d3353032a2f2a1f11843a2031d14089f2b506a8ab0c842a11ffd3022faca02fe426d46cb9b88761b3decb3c78886d46cb9387bc81d26cafae5f597b498ba9b51b2cfa2ff567474d1e34fa037fbd3afacfbf69b45fc09e74e80feee037a3de00e9e93079effdebcfdf3367bd9679396c36a365d1bb8378721bc187cb0832743f9d3d26f5a77903a3a64067bd9682e384daba6016abfa3ceabf0f8d1d3623255a7a12f6473275f3977f5e32ec03fbb6eec88c956500f96c36a364f7cfdeda34fbd34eadc0f1cc5b69cfbf6f4d14f34f3e983c733001ce9e0ce8f7b03ab96da79f4ea6cf7b2fafdfc9fc64e87f3aafecf1a3a700e8e99019ef6517efe6436a364f79fa60367bd9671f2d86d46ca1d1d398b9efeace9bfb7af3df451cfa42d73f7903cfddd9ff77d13e8bf819e7d2117ed380d9ef654105475c9d0e6e7d26674d3fbd740b8279f4e00d1b800d17e66f3f2c0ce8e9d53cfa69ebfb7f09b562d8ce9161a721bc1bf7151d727439b474d8ce8df87a73f70fbd38b47ad37f4d1ab7cc1e7bf479d3cb09b9fb9e9d1bf9fad1ef41b3decbd24c7478fddd91cc9d68d7c3d64464a74a6316da327439b861cb977f0c3bb96ec88c94e9aff6f647327487c68bf0f8d17e1f1a2fc269762f79fe3da6c1e69c9b7378fdcc37b5fa9f15be96aba37ea4bb1cf98de89e86e59477cd937a94ce6a8ac0595db5c0a1b5ce7a8a167e82a05a5c5f51842d4b5a8f508d9bd9abfa5242cb40d25fa523b3");
        Inspector.inspect(data, "Data");
        Decoder decoder = new Decoder(0x4000, 0x1000);
        final NetGuardEncoder encoder = new NetGuardEncoder(0x100);
        decoder.decode(new ByteArrayInputStream(data), new HeaderListener() {
            @Override
            public void addHeader(byte[] name, byte[] value, boolean sensitive) {
                System.out.println("addHeader name=" + new String(name) + ", value=" + new String(value) + ", sensitive=" + sensitive);
                try {
                    encoder.encodeHeader(buffer, name, value, sensitive);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        });
        byte[] out = buffer.toByteArray();
        Inspector.inspect(out, "Out");
    }

}

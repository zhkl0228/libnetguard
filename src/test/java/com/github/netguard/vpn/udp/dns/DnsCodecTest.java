package com.github.netguard.vpn.udp.dns;

import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 用 resources 里录下的真实报文校验 DNS 编解码：查询/应答都能解、应答重新编码后语义不变、
 * 不符合样本形态的报文抛出带十六进制的异常。
 */
public class DnsCodecTest extends TestCase {

    private static Map<String, String[]> load(String resource) throws Exception {
        Map<String, String[]> samples = new LinkedHashMap<>();
        try (InputStream in = DnsCodecTest.class.getResourceAsStream(resource)) {
            assertNotNull(resource, in);
            for (String line : IOUtils.readLines(in, StandardCharsets.UTF_8)) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split(" ");
                samples.put(parts[0], Arrays.copyOfRange(parts, 1, parts.length));
            }
        }
        return samples;
    }

    private static byte[] hex(String s) throws Exception {
        return Hex.decodeHex(s);
    }

    private static DnsQuery query(String hex) throws Exception {
        byte[] data = hex(hex);
        return DnsQuery.decode(data, 0, data.length);
    }

    private static DnsResponse response(DnsQuery query, byte[] data) {
        return DnsResponse.decode(data, 0, data.length, id -> id == query.getId() ? query : null);
    }

    private static void assertThrowsWithHex(Runnable runnable, String expectedReason) {
        try {
            runnable.run();
            fail("expected IllegalArgumentException: " + expectedReason);
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expectedReason));
            assertTrue(e.getMessage(), e.getMessage().contains("hex="));
        }
    }

    public void testClientQueries() throws Exception {
        Map<String, String[]> samples = load("queries.txt");
        assertEquals(5, samples.size());
        for (Map.Entry<String, String[]> entry : samples.entrySet()) {
            DnsQuery q = query(entry.getValue()[0]);
            assertTrue(entry.getKey(), q.getName().equals("www.baidu.com") || q.getName().equals("www.apple.com"));
        }
        DnsQuery a = query(samples.get("dig_a")[0]);
        assertEquals(DnsRecord.TYPE_A, a.getType());
        assertEquals(1232, a.maxResponseSize());
        assertEquals(DnsRecord.TYPE_AAAA, query(samples.get("dig_aaaa")[0]).getType());
        assertEquals(DnsRecord.TYPE_HTTPS, query(samples.get("dig_https")[0]).getType());
        assertEquals(512, query(samples.get("dig_noedns")[0]).maxResponseSize());
        assertEquals(512, query(samples.get("nslookup_a")[0]).maxResponseSize());
    }

    /** 每条真实应答都能解，重新编码再解码后记录完全一致。 */
    public void testUpstreamResponsesRoundTrip() throws Exception {
        Map<String, String[]> samples = load("responses.txt");
        assertEquals(18, samples.size());
        for (Map.Entry<String, String[]> entry : samples.entrySet()) {
            DnsQuery q = query(entry.getValue()[0]);
            DnsResponse r = response(q, hex(entry.getValue()[1]));
            DnsResponse again = response(q, r.encode());
            assertEquals(entry.getKey(), r.getRcode(), again.getRcode());
            assertEquals(entry.getKey(), r.getAnswers(), again.getAnswers());
            assertEquals(entry.getKey(), r.getAuthorities(), again.getAuthorities());
            assertEquals(entry.getKey(), r.getAdditionals(), again.getAdditionals());
            assertEquals(entry.getKey(), r.toString(), again.toString());
        }
    }

    /** CNAME 链：rdata 和后续 owner name 都用了压缩指针，指针还指向前一条记录的 rdata。 */
    public void testCnameChain() throws Exception {
        String[] sample = load("responses.txt").get("google_baidu_a");
        DnsQuery q = query(sample[0]);
        DnsResponse r = response(q, hex(sample[1]));
        List<DnsRecord> answers = r.getAnswers();
        assertEquals(4, answers.size());
        assertEquals("www.baidu.com", answers.get(0).getName());
        assertEquals("www.a.shifen.com", answers.get(0).getTarget());
        assertEquals("www.a.shifen.com", answers.get(1).getName());
        assertEquals("www.wshifen.com", answers.get(1).getTarget());
        assertEquals(DnsRecord.TYPE_A, answers.get(2).getType());
        assertEquals("www.wshifen.com", answers.get(2).getName());
        assertTrue(answers.get(2).getAddress() instanceof Inet4Address);
    }

    public void testNxdomainWithSoa() throws Exception {
        String[] sample = load("responses.txt").get("ali_nxdomain");
        DnsResponse r = response(query(sample[0]), hex(sample[1]));
        assertEquals(DnsResponse.RCODE_NXDOMAIN, r.getRcode());
        assertTrue(r.getAnswers().isEmpty());
        assertEquals(1, r.getAuthorities().size());
        assertEquals(DnsRecord.TYPE_SOA, r.getAuthorities().get(0).getType());
        assertEquals("example.com", r.getAuthorities().get(0).getName());
    }

    public void testHttpsRecordKeptVerbatim() throws Exception {
        String[] sample = load("responses.txt").get("google_cloudflare_https");
        DnsResponse r = response(query(sample[0]), hex(sample[1]));
        assertEquals(1, r.getAnswers().size());
        DnsRecord https = r.getAnswers().get(0);
        assertEquals(DnsRecord.TYPE_HTTPS, https.getType());
        assertEquals("0001000001000602683302683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5",
                Hex.encodeHexString(https.getRdata()));
    }

    /** 不带 OPT 的查询，阿里 DNS 也会回 OPT。 */
    public void testOptInResponseToQueryWithoutEdns() throws Exception {
        String[] sample = load("responses.txt").get("ali_qq_a_noedns");
        DnsQuery q = query(sample[0]);
        assertEquals(512, q.maxResponseSize());
        DnsResponse r = response(q, hex(sample[1]));
        assertTrue(r.toString(), r.toString().contains("EDNS{udp=1232"));
    }

    public void testReplyAndFilter() throws Exception {
        String[] sample = load("responses.txt").get("google_baidu_a");
        DnsQuery q = query(sample[0]);
        Inet4Address fakeIp = (Inet4Address) InetAddress.getByName("192.168.31.88");

        DnsResponse reply = q.reply();
        reply.getAnswers().add(DnsRecord.a("www.baidu.com", 3600, fakeIp));
        DnsResponse decoded = response(q, reply.encode());
        assertEquals(DnsResponse.RCODE_NOERROR, decoded.getRcode());
        assertEquals(reply.getAnswers(), decoded.getAnswers());
        assertEquals(fakeIp, decoded.getAnswers().get(0).getAddress());

        DnsResponse upstream = response(q, hex(sample[1]));
        upstream.getAnswers().add(DnsRecord.a("www.baidu.com", 60, fakeIp));
        DnsResponse filtered = response(q, upstream.encode());
        assertEquals(5, filtered.getAnswers().size());
        assertEquals(fakeIp, filtered.getAnswers().get(4).getAddress());

        DnsResponse blocked = q.reply();
        blocked.setRcode(DnsResponse.RCODE_NXDOMAIN);
        assertEquals(DnsResponse.RCODE_NXDOMAIN, response(q, blocked.encode()).getRcode());
    }

    public void testEncodedResponseMustFitClient() throws Exception {
        DnsQuery q = query(load("queries.txt").get("nslookup_a")[0]); // 无 OPT，上限 512
        DnsResponse reply = q.reply();
        for (int i = 0; i < 40; i++) {
            reply.getAnswers().add(DnsRecord.a("www.baidu.com", 60, (Inet4Address) InetAddress.getByName("10.0.0." + i)));
        }
        try {
            reply.encode();
            fail("expected IllegalStateException");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("exceeds client limit 512"));
        }
    }

    public void testRejectsMalformed() throws Exception {
        String[] sample = load("responses.txt").get("google_baidu_a");
        DnsQuery q = query(sample[0]);
        byte[] response = hex(sample[1]);

        byte[] trailing = Arrays.copyOf(response, response.length + 1);
        assertThrowsWithHex(() -> response(q, trailing), "1 trailing bytes");

        byte[] truncated = Arrays.copyOf(response, response.length - 1);
        assertThrowsWithHex(() -> response(q, truncated), "remaining");

        byte[] wrongId = response.clone();
        wrongId[1] ^= 1;
        assertThrowsWithHex(() -> response(q, wrongId), "matches no pending query");

        byte[] tc = response.clone();
        tc[2] |= 0x02;
        assertThrowsWithHex(() -> response(q, tc), "truncated response");

        // 第一条应答记录（CNAME）在问题段之后：12 字节头 + 15 字节名字 + 4 字节类型/class，
        // owner name 是 2 字节指针，随后就是类型。改成 TXT(16) 应当因未见过的类型被拒。
        byte[] unknownType = response.clone();
        int typeOffset = 12 + 15 + 4 + 2;
        assertEquals(DnsRecord.TYPE_CNAME, unknownType[typeOffset + 1]);
        unknownType[typeOffset + 1] = 16;
        assertThrowsWithHex(() -> response(q, unknownType), "unsupported type=16");

        // 让这个指针指向自己：只许向前跳
        byte[] selfPointer = response.clone();
        int ownerOffset = 12 + 15 + 4;
        selfPointer[ownerOffset] = (byte) (0xc0 | (ownerOffset >>> 8));
        selfPointer[ownerOffset + 1] = (byte) ownerOffset;
        assertThrowsWithHex(() -> response(q, selfPointer), "compression pointer target=" + ownerOffset);

        byte[] query = hex(load("queries.txt").get("dig_a")[0]);
        byte[] notQuery = query.clone();
        notQuery[2] |= (byte) 0x80; // QR=1
        assertThrowsWithHex(() -> DnsQuery.decode(notQuery, 0, notQuery.length), "has bits outside RD/AD/CD");

        byte[] twoQuestions = query.clone();
        twoQuestions[5] = 2;
        assertThrowsWithHex(() -> DnsQuery.decode(twoQuestions, 0, twoQuestions.length), "qd=2");
    }
}

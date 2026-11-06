# 协议分析与算法核对

这是 libnetguard 相对 mitmproxy/Charles 的不可替代之处：解码器是你自己的 Java 代码，和你复刻客户端
的实现跑在同一个 JVM 里。用好这一点。

## 1. 复用客户端自己的类解抓到的字节

解包用的 protobuf / 编解码 / 分帧类，和你复刻客户端构造请求用的**是同一套**——同一份代码既解又建，
本身就是交叉校验：解不出来说明理解错了，解出来又能原样建回去说明理解对了。

- protobuf 协议：`Session` / `ForwardHandler` 里分完帧，直接 `XxxMessage.parseFrom(frame)`，用的就是
  复刻客户端那套 protoc 生成的类，消息 tag 常量也引用客户端代码里的那份。
- 自定义序列化（TL、私有 TLV 之类）：解抓到的帧用客户端的 codec 的 `deserialize`，别为抓包另写一份。

所以写新解码器时，**先找复刻项目里现成的协议类复用，不要另起炉灶重写一份**。两份实现迟早会悄悄
分叉，到时抓包解得出、自己构造的请求却被服务端拒，还查不出差在哪。

## 2. 先原始字节、后解析视图

见 `decoding.md` 的同名小节。核心：空白、键序、重复键、分帧边界、字段实际排列这些「解析后就还原
不回来」的信息，往往正是服务端的反爬 / 校验依据。打印时先用 `rawBody(label, data)` 打原始字节，
自己的解析视图**另加**在后面，别替换原始那段。

真踩过的例子：某个 JSON-RPC 接口的反爬，是在 body 编完之后往 `"method":"` 里插空格，插一个还是两个
由请求 id 算出来。只看格式化后的 JSON 这个字节根本看不出来，抓包和自己构造的请求会长得一模一样。
所以原始和格式化各打一份：

```java
static String jsonBody(byte[] data) {
    String raw = new String(data, StandardCharsets.UTF_8);
    return data.length + " bytes: " + raw + '\n' + JSON.parseObject(raw).toString(SerializerFeature.PrettyFormat);
}
```

## 3. 把抓到的字节当 golden fixture 喂 JUnit

这是「我对协议/算法的理解 == 真实字节」的硬标准，两种写法：

```java
// (a) Captured hex, hard-coded -> decode -> assert fields
byte[] captured = Hex.decodeHex("07fff70541...");
MyPacket p = new MyPacketDecoder().decode(captured);
assertEquals(..., p.getXxx());
// Signatures, certificates and timestamps carried in the packet can be checked in the same test

// (b) Decode then re-encode; the round trip must be byte-for-byte equal
byte[] captured = readHex("hex.txt");
MyMessage msg = codec.deserialize(captured);
assertArrayEquals(captured, msg.serialize());   // any difference = the model of the protocol is off
```

更严一点的做法是在解码器里**运行时就强制 round-trip**：解出来的对象立刻再序列化一次，和抓到的字节
不相等就抛（带上两份 hex）。这样理解偏差在第一次抓包时就暴露，不用等写测试。

算法核对（签名、加密、padding 计算、密钥派生）也走这条路：拿真机抓到的密文/签名，用自己实现的算法
复现，断言一致——例如签名结果、对称加密的测试向量、DH 共享密钥、padding 之后的长度。

## 4. 对齐 TLS 指纹排除干扰

分析反爬时，先用 `ImpersonatorFactory` 把 MITM 上游腿的 TLS 指纹对齐成真实浏览器（见 `routing.md`），
排除「因为指纹不对被拦」这个变量，再看协议本身。判断某个校验到底看不看指纹，就用不同指纹各打一遍
对比。

## 5. MITM 实战踩过的坑

- **自己出去的连接指纹变了会被风控拦。** Cloudflare `cf_clearance`、Scrapfly 等把令牌和 JA3 绑定，
  MITM 自己连上游的 JA3 和客户端不一样 → 403 / 拿不到令牌。用 `configClientSSLContext(ImpersonatorFactory…)`
  对齐。
- **h2 MITM 可能弄坏 Cloudflare 保护的单页应用**（遇到过一开始直接打不开）。先用 `CONNECT_SSL`
  确认能用，再换 `FILTER_H2`。
- **WebSocket 极其敏感**：注入帧会被服务端重置连接；改写帧会让客户端一直转圈。非必要就 `onFrame`
  返回入参原样透传（字节保真）。
- **ALPN 降级**：不想让某主机被升级到 h2（想走更好解的 http/1.1），就在 acceptTcp 里
  `connectRequest.applicationLayerProtocols.remove("h2")`。这个列表是可变的，框架之后就用它和上游协商，
  所以需要时也可以往里追加客户端要的自定义 ALPN 标识。
- **非 TLS 专有协议 netguard 不能直接 MITM**：走 `CONNECT_TCP + ForwardHandler` 或 `redirectAddress`，
  密钥另想办法（见 `raw-stream.md`）。
- **replay 只在 `BaseVpnListener` 下有效**；lambda listener 配 `withReplayLogFile` 会在 `startServer()` 时抛。
- **一个 decoder 服务所有连接**（`BaseVpnListener` 只建一个），按连接存的状态用并发容器、按会话 key 分开。
- 多个 capture 跑在一个 JVM 时注意别重复注册 BouncyCastle（`if (Security.getProvider(...) == null)`）。

## 严谨解析：解码代码就是协议文档

写分帧 / 消息分派 / 字段提取 / 二进制格式时，**只解析有真实抓包样本支撑的情况，其余一律抛异常**，
异常信息里带够补样本用的东西：消息类型、期望与实到的标签、原始字节十六进制。

- 不许 `catch (Exception) { return null; }`，不许兜底 `return`，不许把没实际收到过的分支写进「已知」列表。
- **分派用的「这条不归我管」可以返回 null；已经认出是这条消息之后再对不上，必须抛。** 这两件事绝不
  能是同一行代码。
- 长度前缀、消费字节数、扩展类型标签这类校验一个都不能省，即使解析器「看起来能跑」。
- 枚举已知情况时逐条自问「这个我真的收到过吗」，没收到过的不许写进去。
- 探测型方法（「这堆字节是不是 X」，如 `acceptTcp` 里按 prologue 判协议）可以吞异常返回「不是」，
  但要在注释里和解码型方法明确分开。

**为什么**：宽容的解析出错时是静默的——拿到 null 的调用方会一直等到超时，日志里一个字都没有，这是
最难查的故障；服务端改了协议也完全无感。**抛异常本身就是拿样本的手段**：吞掉就什么都学不到，抛出来
才会拿到一份带完整信息的真实样本，照着它补一条分支。所以误拒真实流量不是代价，是收益，前提是异常
信息足够完整。

解已经读成 Map/List 的数据（接口 JSON、配置 YAML）时，**字段是什么类型就按样本直接强转**，不逐个
字段 `instanceof` 判类型再手写报错；在解析单个节点的入口统一 catch 运行时异常，连同该节点原文一起
报出来（强转抛的 `ClassCastException` 本身就是「先抛」）。

### 不是所有没见过的情况都要失败

「拿样本」不只抛异常一种，**记一条带完整样本的 `log.warn` 同样能拿到样本**。没见过的情况到底抛异常
还是 WARN 后继续，看有没有一个**确定、安全**的继续方式：标准语义已说明含义、或有不依赖猜测的退路，
就 WARN 后继续，别让真实流量为「还没见过」买单（例：上游代理回了没见过的 HTTP CONNECT 响应，
状态码 200 按语义隧道已通照常用，非 200 就换下一个出口）；往下走就会把它当别的东西用、悄悄解析错的，
照旧抛。WARN 里带的东西和异常一样要够补样本：对方是谁、发了什么、原始字节 hex、这次按什么处理的。

# 路由决策：acceptTcp / acceptUdp

每条 TCP 连接问一次 `acceptTcp(ConnectRequest)`，每个 UDP 流问一次 `acceptUdp(PacketRequest)`。
在 `PacketDecoder` 子类里覆写它们，返回怎么处理这条连接。**这是整个库的核心决策点。**

## 默认实现（不覆写、或落到 super 时）

```java
// PacketDecoder.acceptTcp, in order:
isAppleHost()   -> connectTcpDirect()   // Apple hosts pass through
isAndroidHost() -> disconnect()         // Google hosts are dropped
isSSL()         -> disconnect()         // every other TLS connection is dropped
otherwise       -> CONNECT_TCP          // plain TCP passes through

// PacketDecoder.acceptUdp:
DNS, or no HTTP/3 ALPN -> Forward
HTTP/3 (QUIC)          -> Discard       // forces the app to fall back to TCP
```

所以覆写 `acceptTcp` 时，**不关心的连接显式 `connectTcpDirect()`**，不要 `return super.acceptTcp(...)`
兜底——那会把所有 TLS 断掉。默认丢弃 QUIC 倒是常常正合适：App 回落到 TCP 之后更好 MITM。

框架这边：`acceptTcp` 返回 null 等于 `CONNECT_TCP` 直连；抛异常会被 catch、记一条 WARN
（`acceptTcp failed`）后按直连处理。`acceptUdp` 返回 null 等于 `Forward`。

## AllowRule（TCP）

```java
public enum AllowRule {
    DISCONNECT,    // refuse the connection
    CONNECT_SSL,   // TLS MITM: decrypt and decode
    FILTER_H2,     // TLS MITM plus HTTP/2 frame-level filtering (Http2Filter)
    CONNECT_TCP,   // plain pass-through, no decryption (can attach a ForwardHandler)
    __READ_MORE_PROLOGUE, __CUSTOM_HANDLE   // internal: use readMorePrologue() / handle() instead
}
```

- `CONNECT_SSL` 要求设备已信任根证书。对非 TLS 连接返回它，效果就是直连透传。
- `FILTER_H2` 要**同时满足**下面三条才进 h2 帧管线，否则等同 `CONNECT_SSL`：
  `getH2Filter()` 非 null、和上游协商出的 ALPN 是 `h2`、`filter.filterHost(hostName, false)` 返回 true。
- 拿不准就用 `connectRequest.tryMITM(filterH2)`（见下）。

## AcceptTcpResult 的构造

```java
// 1) builder
AcceptTcpResult.builder(AllowRule.CONNECT_SSL)
        .configClientSSLContext(sslContext)              // SSLContext for the upstream TLS leg (fingerprint)
        .enableSocksProxy("1.2.3.4", 1080)               // go out via SOCKS, target addressed by IP
        .enableSocksProxyV5("127.0.0.1", 1080, host)     // go out via SOCKS5, target addressed by host name
        .redirectAddress("127.0.0.1", 8888)              // connect to this ip:port instead of the original
        .setForwardHandler(handler)                      // take over the raw byte streams, see raw-stream.md
        .build();

// 2) shortcuts on ConnectRequest
connectRequest.connectTcpDirect()       // = builder(CONNECT_TCP); returns the builder
connectRequest.tryMITM(filterH2)        // TLS and filterH2 and ALPN has h2 -> FILTER_H2; TLS -> CONNECT_SSL; else direct; returns the builder
connectRequest.disconnect()             // = builder(DISCONNECT).build(); also prints a line to stderr
connectRequest.readMorePrologue(n)      // ask for n bytes of prologue in total, then acceptTcp runs again
connectRequest.handle(customHandler)    // hand the client side to a CustomHandler, see raw-stream.md
```

几个容易误解的点：

- **SNI 永远是客户端原来的 `hostName`**。`redirectAddress` 只改 TCP 连到哪个 ip:port，TLS 握手照旧用
  原主机名。
- `setRedirectHost(host)` / `build(host)` / `enableSocksProxyV5(..., host)` 设的是「经 SOCKS 出去时，
  让代理去解析的目标主机名」，只在走 SOCKS 时用到；不走代理时没有作用。`tryMITM` 会自动设成
  `hostName`。2 参的 `enableSocksProxy` 不设，代理收到的是 IP。
- SOCKS 以外的代理类型（`Proxy.Type.HTTP`）不支持，`enableSocksProxyV5(Proxy, ...)` 直接抛
  `IllegalArgumentException`。
- `CustomHandler` 只认 `connectRequest.handle(h)`；在别的 rule 的 builder 上 `setCustomHandler(h)`
  不会生效。

典型返回：

```java
// Not ours: pass through untouched
return connectRequest.connectTcpDirect().build();

// Decrypt one HTTPS host
if (host != null && host.endsWith(".example.com")) {
    return AcceptTcpResult.builder(AllowRule.CONNECT_SSL).build();
}

// HTTP/2 frame-level filtering (also override getH2Filter())
if ("api.example.com".equals(host)) {
    return AcceptTcpResult.builder(AllowRule.FILTER_H2).build();
}

// One-liner MITM: picks CONNECT_SSL / FILTER_H2 by ALPN
return connectRequest.tryMITM(true).build();

// Block
return connectRequest.disconnect();
```

## ConnectRequest：拿什么来判

| 成员 / 方法 | 含义 |
| --- | --- |
| `hostName` | TLS ClientHello 里的 SNI。**明文 HTTP 和没带 SNI 的 TLS 都是 null**；明文 HTTP 的主机名从 `httpRequest.headers().get("Host")` 取 |
| `serverIp` / `port` | 目标 IP / 端口 |
| `applicationLayerProtocols` | 客户端 ALPN 列表，**可变**，框架之后就用这个列表和上游协商。`contains("h2")` 判 HTTP/2；`remove("h2")` 可强制降级到 http/1.1 |
| `isSSL()` | 首部能解析成 TLS ClientHello |
| `isHttp()` | 是不是明文 HTTP 请求（`httpRequest != null`） |
| `httpRequest` | 明文 HTTP 时的 Netty `HttpRequest`（可读 header） |
| `getPrologue()` | 已读到的首部原始字节（`byte[]`）。用来嗅探非 HTTP/TLS 的专有协议 |
| `readMorePrologue(n)` | 现有字节不够认协议时返回它，见下 |
| `getTlsSignature()` | TLS 指纹 `TlsSignature`：`getJa3Text()`/`getJa3nText()`/`getJa4Text()`/`getPeetPrintText()`/`getScrapflyFP()`。可能为 null |
| `queryApplications()` | **VPN 接入（Android）专有**：发起这条连接的 App 列表 `Application[]`，有 `getPackageName()`/`getLabel()`/`getVersionCode()`。socks/http 代理接入拿不到 |
| `getClientOS()` | 客户端平台 |
| `isAppleHost()` / `isAndroidHost()` | 按主机名后缀的便捷判断（`.apple.com`/`.icloud.com`…；`.googleapis.com`/`.google.com`/`www.gstatic.com`）。`isAppleHost` 还认 `com.apple.` 开头的 User-Agent |
| `getExtraData()` | 客户端带的附加数据 |

**按 App 身份精确分流**（VPN 接入的独特价值）：

```java
Application[] apps = connectRequest.queryApplications();
if (apps != null) {
    for (Application app : apps) {
        if ("com.example.app".equals(app.getPackageName())) {
            return connectRequest.tryMITM(false).build();
        }
    }
}
```

**按首字节嗅探非 TLS 专有协议**：

```java
static final byte[] MAGIC = {'X', 'Y', 0x00, 0x01};   // the protocol's magic, taken from a real capture

byte[] head = connectRequest.getPrologue();
if (head.length < MAGIC.length) {
    return connectRequest.readMorePrologue(MAGIC.length);
}
if (Arrays.equals(Arrays.copyOf(head, MAGIC.length), MAGIC)) {
    return connectRequest.connectTcpDirect().setForwardHandler(new MyHandler()).build();
}
```

`readMorePrologue(n)` 的规矩：

- `n` 是**总长度**，必须大于当前 `getPrologue().length`，否则抛 `IllegalStateException`
  （被框架记成 `acceptTcp failed`）。
- 框架最多等 800ms 去读。**等不到就带着原来的 prologue 再调一次 `acceptTcp`**——所以第二次进来时
  长度可能还是不够，这时要做决定（直连 / 断开），不要无条件再要，否则会一直循环。
- 非 TLS 连接的 `getPrologue()` 只有第一次调用时已经到达的字节（最多 128），可能只有 1 字节，
  所以按 magic 认协议前先判长度。
- `acceptTcp` 要等客户端先发出至少一个字节才会被调用。服务端先说话的协议（客户端连上后等服务端
  发 banner）没法靠 prologue 认，只能按 `serverIp`/`port`/App 身份路由。

## 对齐上游 TLS 指纹（反爬 / 风控）

MITM 时，netguard 自己连上游那条腿的 TLS 指纹默认不是真实浏览器的。很多反爬 / 风控（Cloudflare
`cf_clearance`、Scrapfly 等）**把 cookie/令牌和 JA3 指纹绑定**——指纹一对不上就 403 或拿不到令牌。
用 `ImpersonatorFactory` 模仿真实客户端指纹：

```java
return AcceptTcpResult.builder(AllowRule.CONNECT_SSL)
        .configClientSSLContext(ImpersonatorFactory.macChrome().newSSLContext(null, null))
        .build();
// Also: macSafari(), macFirefox(), ios(), android()
```

证书校验跟着变：**不配 `configClientSSLContext` 时 netguard 信任上游任何证书**；
`newSSLContext(null, null)` 用默认信任库校验上游证书，上游是自签 / 内网证书就会握手失败，
这时换成 `newTrustAnyCertificateSSLContext()`。

也可反过来用：想判断某个反爬到底看不看 TLS 指纹，就把流量路由到 `tls.browserleaks.com` /
`tools.scrapfly.io` 用不同指纹各打一遍，对比结果。

## acceptUdp / AcceptUdpResult（UDP / QUIC / DNS）

```java
public enum AcceptRule { Forward, Discard, QUIC_MITM, FILTER_H3 }

@Override
public AcceptUdpResult acceptUdp(PacketRequest packetRequest) {
    if (packetRequest.dnsQuery != null) {
        return AcceptUdpResult.rule(AcceptRule.Forward);    // DNS: let it through (DNSFilter can rewrite)
    }
    if (!packetRequest.applicationLayerProtocols.isEmpty()) {
        return AcceptUdpResult.rule(AcceptRule.FILTER_H3);  // HTTP/3: reuses getH2Filter()
    }
    return AcceptUdpResult.rule(AcceptRule.Forward)
            .setProxyHandler(new MyUdpHandler());           // raw UDP packets, see raw-stream.md
}
```

- `PacketRequest` 判据和 `ConnectRequest` 类似：`hostName`、`serverIp`/`port`、`applicationLayerProtocols`
  （QUIC ClientHello 的 ALPN）、`dnsQuery`（非 null 即 DNS 查询）、`getPrologue()`、`getTlsSignature()`
  （QUIC 走 JA3）、`queryApplications()`、`disconnect()`（= `Discard`）。没有 `readMorePrologue`。
- `QUIC_MITM` / `FILTER_H3` 要 `hostName` 和 ALPN 都有，否则退回 `Forward`。`FILTER_H3` 复用
  `getH2Filter()`，`filterHost(hostName, true)` 的第二个参数就是在说这是 HTTP/3。
- `DNSFilter.cancelDnsQuery` 在 `acceptUdp` **之前**就对每个 DNS 包调用了，见 `decoding.md`。
- QUIC MITM 走 kwik（`getQuicProxyProvider()` 默认 `QuicProxyProvider.kwik()`）。能接手的 HTTP/3 ALPN
  标识见 `PacketRequest.HTTP3_APPLICATION_LAYER_PROTOCOLS`（`h3`、`h3-alias-02`，逐条有样本支撑；
  加新项之前必须先有真实样本）。

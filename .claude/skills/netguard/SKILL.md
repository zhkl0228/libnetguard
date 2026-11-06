---
name: netguard
description: >-
  用 libnetguard（Maven com.github.zhkl0228:netguard）这个可嵌入的 Java 抓包 / MITM 库，
  把某个 App（手机或桌面）的流量接过来解密、解码、必要时改写，用来逆向分析它的网络协议、
  核对加密/签名算法、复刻客户端请求。只要任务涉及：起一个 VPN / socks / http 代理服务端抓某个
  App 的包、对 HTTPS 做中间人、拿 HTTP/2 或 WebSocket 或 DNS 或 QUIC 的内容、解某个专有二进制
  协议（protobuf / 自定义分帧 / 自定义加密握手之类）、用抓到的字节喂 JUnit 做算法核对、
  用 ImpersonatorFactory 模仿浏览器 TLS 指纹绕反爬——就用这个 skill。写 acceptTcp 路由、
  PacketDecoder、SessionFactory、Http2Filter、WebSocketFilter、DNSFilter、ForwardHandler/CustomHandler、
  AcceptTcpResult 时也用它。涉及 VpnServerBuilder、BaseVpnListener、ConnectRequest、AllowRule、
  JA3/JA4 指纹、根证书安装、pre-master secret keylog 时同样适用。
---

# libnetguard：嵌入式抓包 / MITM 库

libnetguard 和 mitmproxy、Charles 的区别只有一条，但很要紧：**它是个库，不是个进程**。
解码器就是你自己的 Java 代码，跟被分析客户端的复刻实现跑在同一个 JVM 里——于是抓包解出来的
protobuf / 自定义编解码对象和你复刻客户端用的可以是**同一套类**，能直接写进 JUnit
拿抓到的字节和自己构造的请求逐字节比对。**要在浏览器里看流量用别的工具更省事；要用代码分析
协议、再用代码复刻它、顺带核对加密签名算法，这个库的位置很难被替代。** 这个 skill 的全部内容
都是围绕后一件事。

## 心智模型：一条连接的生命周期

1. 设备流量通过**接入层**进来（VPN 客户端 / socks5 / http 代理，见 `references/capture-setup.md`）。
2. 每条 TCP 连接问一次 `acceptTcp(ConnectRequest)`，每个 UDP 流问一次 `acceptUdp(PacketRequest)`——
   你在这里**按主机名 / ALPN / 首字节 / App 身份决定怎么处理**：直连透传、解密 MITM、HTTP/2 帧级
   过滤、断开、或把原始流交给自己的 handler。这是整个库的核心决策点，见 `references/routing.md`。
3. 被 MITM 的连接，解密后的内容通过 **`PacketDecoder` 的回调**和各种 **Filter** 交到你手上，
   可观测、可改写，见 `references/decoding.md`。
4. 专有二进制协议（非 HTTP、甚至非 TLS）用 **`ForwardHandler` / `CustomHandler` 接管原始流**
   自己解，见 `references/raw-stream.md`。

## 最小骨架

```java
public class Main {
    public static void main(String[] args) throws Exception {
        VpnServer vpnServer = VpnServerBuilder.create()
                .withPort(20240)
                .enableBroadcast(30)                    // LAN discovery for the VPN client app, every 30s
                .enableProxy()                          // also accept socks4/5 and http(s) proxy clients
                .withReplayLogFile(new File("target/replay.log"))   // optional; requires BaseVpnListener
                .withVpnListener(new BaseVpnListener() {
                    @Override
                    protected IPacketCapture createPacketCapture() {
                        return new MyDecoder();         // called once, shared by every client and connection
                    }
                })
                .startServer();
        String lanIp = Inspector.detectLanIP();         // may return null
        System.out.printf("vpn server on %s:%d%n", lanIp == null ? "127.0.0.1" : lanIp, vpnServer.getPort());
        vpnServer.waitShutdown();                        // blocks on stdin; type q / exit to stop
    }
}
```

`MyDecoder extends PacketDecoder`：覆写 `acceptTcp` 做路由（**必须覆写**，默认实现会断开所有 TLS
连接，见下面「先知道的几件事」）、覆写 `onRequest`/`onResponse` 看内容、覆写 `getH2Filter()` 等挂过滤器。
能跑的完整例子在仓库里：`src/test/java/com/github/netguard/Main.java`。

## 接入方式：优先 VPN

| 接入方式 | 怎么开 | 设备侧 | 适用 |
| --- | --- | --- | --- |
| **VPN（首选）** | `enableBroadcast(30)` + 配套 VPN 客户端 | 装 iPhoneVPN / AndroidVPN / SwiftConnect(Mac) 等，连本服务端 | **网络隔离最精准**；Android 下还能 `connectRequest.queryApplications()` 拿到发起连接的 App 身份（包名/版本），按 App 精确分流 |
| socks5 / http 代理 | `enableProxy()` | 设备系统代理指向 `服务端IP:端口` | 快速验证、桌面程序；拿不到 App 身份 |

**默认优先 VPN 接入**——它把该 App 的流量在网络层隔离出来，不会混进整机其它流量，按 App 过滤也更准。
socks/http 代理作为补充。接入层细节、根证书安装、JDK/JVM 参数见 `references/capture-setup.md`。

## 决策树：一条连接该怎么处理？

在 `acceptTcp(ConnectRequest)` 里，按下面顺序判断（完整 API 和每种 builder 链见 `references/routing.md`）：

```
是我关心的目标 App / 主机吗？（hostName / 明文 HTTP 看 httpRequest 的 Host 头 / queryApplications()）
├─ 不是 → return connectRequest.connectTcpDirect().build();   直连透传，别碰也别断（App 可能靠它工作）
│         不要落到 super.acceptTcp(...)：默认实现会断开所有 TLS 连接
└─ 是
   ├─ 是 HTTPS（isSSL()）
   │   ├─ 要看明文 → AllowRule.CONNECT_SSL
   │   ├─ 还要按 h2 流逐个看 / 改写 → AllowRule.FILTER_H2，并覆写 getH2Filter()
   │   ├─ 便捷写法：connectRequest.tryMITM(filterH2).build()（按 ALPN 自动选；非 TLS 则直连）
   │   └─ 风控看 TLS 指纹 → 再加 .configClientSSLContext(ImpersonatorFactory.macChrome().newSSLContext(null, null))
   ├─ 是专有二进制协议（按 getPrologue() 首字节认出，非 HTTP/TLS）
   │   → connectTcpDirect().setForwardHandler(myHandler).build()  自己解原始流，见 references/raw-stream.md
   │     （字节不够认：return connectRequest.readMorePrologue(n)，n 是总长度，必须大于已有长度）
   └─ 要屏蔽它 → return connectRequest.disconnect();
```

## 先知道的几件事（都对照过源码，最容易写错）

- **默认 `acceptTcp` 会断开所有 TLS 连接**：Apple 域名直连、Google 域名断开、其余 TLS 断开、
  明文直连。只处理自己关心的主机，其余显式 `connectTcpDirect()`。默认 `acceptUdp` 放行 DNS 和
  普通 UDP，**丢弃 HTTP/3（QUIC）**，逼 App 回落到 TCP——想抓 QUIC 才需要覆写它。
- `acceptTcp` 返回 null 等于直连；里面抛异常会被框架 catch、记一条 WARN（`acceptTcp failed`）后
  按直连处理。连接不会断，但你的路由也没生效——看到这条 WARN 就去修。
- **明文 HTTP 连接的 `hostName` 是 null**（它只来自 TLS 的 SNI），主机名要从
  `connectRequest.httpRequest.headers().get("Host")` 取。
- **`BaseVpnListener.createPacketCapture()` 只在构造器里调一次**，所有客户端、所有连接共用这一个
  decoder，回调来自多个线程——decoder 里的状态要线程安全。
- **两套 HttpRequest**：`PacketDecoder.onRequest/onResponse` 给的是 `com.github.netguard.handler.http.*`；
  `Http2Filter`/`AbstractHttp2Filter` 用的是 Netty 的 `io.netty.handler.codec.http.*`。import 错了会
  报找不到方法。
- `PacketDecoder` 自带的「先原始字节、后解析视图」输出**只在它的 logger 开到 DEBUG 时才打**；
  自己打印时用 `PacketDecoder.rawBody(label, data)`（protected static）输出原始字节。
- `onSSLProxyEstablish` / `onSSLProxyFinish` 是 `final`，不能覆写；`onSSLProxyTx/Rx` 可以覆写，
  但**必须调 `super`**，否则 HTTP 解码和 `SessionFactory` 都收不到数据。

## 协议分析与算法核对（这个库最值钱的用法）

分析一个 App 的协议、核对它的加密/签名算法时，坚持三条（详见 `references/protocol-analysis.md`）：

- **复用客户端自己的类解抓到的字节。** 解包用的 protobuf / 编解码 / 分帧类，和你复刻客户端构造请求用的
  是同一套——同一份代码既解又建，本身就是交叉校验。写新解码器前先在复刻项目里找现成的协议类，
  不要另起炉灶。
- **先原始字节，后解析视图。** 空白、键序、重复键、header 大小写与顺序、分帧边界这些「解析后就还原
  不回来」的信息，往往正是服务端的反爬/校验依据（真踩过：服务端拿 JSON 里多出的一个空格当校验）。
  只看解析视图，自己构造的请求会和真机抓到的长得一模一样，差异无从发现。
- **把抓到的字节当 golden fixture 喂 JUnit。** hex 硬编码 → 解码 → 断言字段；或解码再序列化
  `assertArrayEquals` 要求 round-trip 字节级相等。这是验证「我对协议的理解 == 真实字节」的硬标准。

## 什么时候需要 ForwardHandler / 接管原始流

HTTP(S) 用 `PacketDecoder` 回调 + Filter 就够了；跑在 TLS 里但不是 HTTP 的二进制协议，只看不改用
`SessionFactory`（见 `references/decoding.md`）。遇到 netguard 不认识分帧、甚至不是 TLS 的专有协议：

- `connectTcpDirect().setForwardHandler(h)`：拿到 client/server 两个方向的原始 `InputStream`/
  `OutputStream`，自己分帧、解密、改写、转发。配 `CONNECT_SSL` 时拿到的是 TLS 解密后的明文流
  （前提是这条连接没进 h2 / WebSocket 过滤管线）。
- 或 `.redirectAddress("127.0.0.1", port)`：把原始流导给你另起的本地服务去解。
- 密钥不在流里就得从外部拿（frida 从活 App 导出、从已解密的信令里捞）；在流里自描述、或能坐在
  密钥交换中间现算的，就能直接解。

详见 `references/raw-stream.md`。

## 参考文件

细节都在 `references/` 下，按需读，不要凭记忆写 API：

- `references/capture-setup.md` —— `VpnServerBuilder` 全部选项、两种 `VpnListener` 写法、根证书安装、
  pre-master secret keylog、JDK/JVM 参数、Maven 依赖、输出去向。
- `references/routing.md` —— `acceptTcp`/`acceptUdp` 完整 API：`AllowRule` 各值、`ConnectRequest`/
  `PacketRequest` 所有判据、`AcceptTcpResult` builder 全部链式方法、`ImpersonatorFactory` 指纹对齐、
  `getPrologue()`/`readMorePrologue()` 嗅探非 TLS 协议、两个默认实现的行为。
- `references/decoding.md` —— `PacketDecoder` 构造与所有回调、`SessionFactory`+`Session` 解 TLS 内的
  非 HTTP 二进制流、`Http2Filter`/`AbstractHttp2Filter`、`WebSocketFilter`+`WebSocketInjector`、`DNSFilter`。
- `references/raw-stream.md` —— `ForwardHandler`/`CustomHandler`/`redirectAddress`/`ProxyHandler`
  接管原始流，以及密钥从哪来的三类套路。
- `references/protocol-analysis.md` —— 复用客户端类、golden fixture 测试、算法核对、TLS 指纹对齐、
  MITM 实战里踩过的坑、严谨解析规则。

## 严谨解析（写解码器时务必遵守）

这个库解的是真实协议，解码代码就是协议文档：**只解析有真实抓包样本支撑的情况，其余一律抛异常**，
异常信息带够补样本用的东西（消息类型、期望与实到的标签、原始字节十六进制）。不要
`catch (Exception) { return null; }`，不要兜底 `return`。分派用的「这条不归我管」可以返回 null；
**已经认出是这条消息之后**再对不上，必须抛。完整规则（含什么时候可以 WARN 后继续）见
`references/protocol-analysis.md` 的「严谨解析」一节。

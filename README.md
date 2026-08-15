# libnetguard

可嵌入的 Java 抓包 / MITM 库。跑一个 VPN 服务端（也支持 socks / http 代理和透明代理），
把设备的流量接过来解密、解码、必要时改写。

和 mitmproxy、Charles 这类工具的区别只有一条，但很要紧：**它是个库，不是个进程**。
解码器就是你自己的 Java 代码，跑在同一个 JVM 里——于是抓包解出来的 protobuf 和你实现
客户端用的可以是**同一套 protoc 生成的类**，能直接写进 JUnit 用例，也能拿抓到的字节
和自己构造的请求逐字节比对。要在浏览器里看流量，用别的工具更省事；要用代码分析协议、
再用代码复刻它，这个的位置很难被替代。

```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>netguard</artifactId>
    <version>0.0.12</version>
</dependency>
```

需要 JDK 11。JDK 9 以上跑测试要加
`--add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED`。

## 能解什么

| | 说明 |
| --- | --- |
| HTTP/1.1 | 请求、响应、chunked、multipart |
| HTTP/2 | 帧级转发，`Http2Filter` 能拿到并改写每个流的字节 |
| HTTP/3 / QUIC | 基于 kwik + flupke |
| WebSocket | `WebSocketFilter` 逐帧拿到内容，还能主动注入 |
| DNS | `DNSFilter`，可改应答 |
| TLS | 自签 CA 做 MITM；也可以只导出 pre-master secret 交给 Wireshark |

上游连接的 TLS 指纹可以模仿真实浏览器（`ImpersonatorFactory.macChrome()` 等），
用来排除「被识别成脚本」这类干扰——判断一个反爬校验到底看不看指纹时很有用。

## 起一个服务端

```java
VpnServer vpnServer = VpnServerBuilder.create()
        .withPort(20240)
        .enableTransparentProxying()
        .enableProxy()
        .enableUdpRelay()
        .enablePreMasterSecretsLogFile()
        .withVpnListener(new BaseVpnListener() {
            @Override
            protected IPacketCapture createPacketCapture() {
                return new MyPacketDecoder();
            }
        })
        .startServer();
String lanIp = Inspector.detectLanIP();          // 可能返回 null
System.out.printf("vpn server listen on: %s:%d%n", lanIp == null ? "127.0.0.1" : lanIp, vpnServer.getPort());
vpnServer.waitShutdown();
```

完整例子见 [Main.java](src/test/java/com/github/netguard/Main.java)，里面还有按 SNI
分流、按连接换 TLS 指纹、改 DNS 应答、HTTP/2 过滤器的写法。

客户端（把设备流量导过来）：

- [QianxinVPN](https://appstore.qianxin.com/app/download)
- [iPhoneVPN](https://github.com/zhkl0228/InspectorVpn)
- [AndroidVPN](https://github.com/zhkl0228/AndroidVPN)
- [MacVPN](https://github.com/zhkl0228/SwiftConnect)
- [WindowsVPN](https://github.com/zhkl0228/jna-wintun)

## 写自己的解码器

继承 `PacketDecoder`，覆写关心的回调。构造函数可以顺带落一份 pcap：

```java
static class MyPacketDecoder extends PacketDecoder {
    MyPacketDecoder() {
        super(new File("target/vpn.pcap"), true);
    }

    @Override
    protected void onRequest(HttpSession session,
                             com.github.netguard.handler.http.HttpRequest request) {
        super.onRequest(session, request);   // 先打原始字节，别省
        if ("api.example.com".equals(request.getHost())) {
            // 再打你自己的解析视图
        }
    }
}
```

### 一条经验：先原始字节，再解析视图

`PacketDecoder` 的默认实现**先打 body 的原始字节**（文本原样打，二进制走 hex+ASCII），
然后才是解析出来的头和参数。覆写时请保留 `super` 那一步。

这不是洁癖，是踩出来的。分析 DeepL 的接口时，它的反爬校验看两样东西：`"method":`
后面有几个空格，以及 JSON 的键序。而解码器当时打印的是**解析后重新序列化**的 JSON——
空格被吃掉、键序被重排，于是自己构造的请求和真机抓到的**打印出来一模一样**，
怎么比都比不出差异，白白卡了很久。改成打原始字节，一眼就看见了：

```
request body (271 bytes)
{"jsonrpc":"2.0","method": "LMT_split_text","id":2907,...}
                         ^ 就这一个空格
```

抓包工具最不该做的事，就是把自己的解释当成观测递给你。所以：**原始字节是默认，
解析视图是补充**，顺序不要反。

要更底层的字节，这些回调直接给 `byte[]`，不经任何解析：

- `onSSLProxyTx` / `onSSLProxyRx` —— TLS 解密后的原始流
- `Http2Filter.filterRequest` / `filterResponse` —— HTTP/2 每个流的字节，返回值可改写
- `WebSocketFilter` —— WebSocket 帧内容

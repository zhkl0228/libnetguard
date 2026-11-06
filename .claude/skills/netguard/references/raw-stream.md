# 接管原始流：非 HTTP、甚至非 TLS 的专有协议

HTTP(S) 用 `PacketDecoder` 回调 + Filter 就够；TLS 里的非 HTTP 协议只看不改用 `SessionFactory`
（见 `decoding.md`）。目标 App 跑的是 netguard 不认识分帧和加密的专有协议、或者要改写它，就得接管
原始字节流自己处理。四条路，按需要的控制粒度选：

| 手段 | 拿到什么 | 适用 |
| --- | --- | --- |
| `.setForwardHandler(ForwardHandler)` | client / server 两个方向的 `InputStream`/`OutputStream`，各一个线程 | 要双向看 + 改 + 转发 |
| `connectRequest.handle(CustomHandler)` | 只给 client 侧的 in/out，上游连接你自己建 | 完全自定义（本地应答、自己选出口） |
| `.redirectAddress("127.0.0.1", port)` | 把目标改到本地，流导进你另起的服务 | 协议处理已经是个独立服务 |
| `acceptUdp` 里 `.setProxyHandler(ProxyHandler)` | 每个 UDP 包 | UDP 上的专有协议（媒体流等） |

## ForwardHandler

```java
public interface ForwardHandler {
    default void initContext(ForwardContext context) { }   // optional: both Sockets
    void handleClient(Socket clientSocket, byte[] buf, InputStream clientIn, OutputStream serverOut) throws IOException;
    void handleServer(Socket serverSocket, byte[] buf, InputStream serverIn, OutputStream clientOut) throws IOException;
}
```

- 框架给每个方向起一个线程，`handleClient`（客户端→服务端）和 `handleServer`（服务端→客户端）
  **各调一次**：你在里面自己循环读、分帧、解密、改写、写到对端，直到读到 EOF。**方法返回就表示这个
  方向结束**，框架随即关掉这一侧的流。
- `buf` 是框架分配好的读缓冲，可以直接拿来用。
- prologue（`acceptTcp` 时已经读走的首部字节）已经被推回 `clientIn`，你从第一个字节开始读得到完整流。
- `initContext(ForwardContext)` 在两个线程启动前调用，能拿到两个 `Socket`（API 里的拼写是
  `getClinetSocket()` / `getServerSocket()`）。
- 挂了 `ForwardHandler` 的连接，`PacketDecoder` 的 `onSocketTx/Rx`、`onSSLProxyTx/Rx` 都不会被调，
  HTTP 解码和 `SessionFactory` 也看不到这条流——字节完全归你管。

两种挂法：

```java
// Non-TLS proprietary protocol: raw bytes as they are on the wire
return connectRequest.connectTcpDirect()
        .setForwardHandler(new MyHandler())
        .enableSocksProxy("127.0.0.1", 1080)   // optional upstream SOCKS exit
        .build();

// Proprietary protocol inside TLS that you need to rewrite: decrypted plaintext streams
return AcceptTcpResult.builder(AllowRule.CONNECT_SSL)
        .setForwardHandler(new MyHandler())
        .build();
```

配 `CONNECT_SSL` 时要确认这条连接不会进 h2 / WebSocket 过滤管线（没路由成 `FILTER_H2`、
`WebSocketFilter.filterHost` 对它返回 false），否则字节走的是那两条管线，不经过你的 handler。

## CustomHandler

```java
public interface CustomHandler {
    void handle(InputStream clientInput, OutputStream clientOutput) throws IOException;
}
```

用 `return connectRequest.handle(h);` 返回。只给客户端侧的输入/输出（prologue 同样已推回
`clientInput`），到上游的连接要不要建、怎么建完全由你决定；`handle` 返回后连接就结束。
注意只有 `handle(h)` 这个入口有效，在别的 rule 的 builder 上 `setCustomHandler(h)` 不会生效。

## redirectAddress：导进自建服务

把目标地址改成本地，让流量进你另起的专用服务器去解：

```java
return connectRequest.connectTcpDirect()
        .redirectAddress("127.0.0.1", myServerPort)   // netguard only relays the raw bytes there
        .build();
```

适合协议处理（握手、解密、再转发到真实服务端）已经写成一个独立服务的情况。你的服务看到的对端是
netguard，不是设备；需要原始目标地址就得自己从 `acceptTcp` 里记下来传过去。

## UDP：ProxyHandler

UDP 原始包（如音视频的 STUN/RTP/RTCP），用 `acceptUdp` 返回里 `.setProxyHandler(...)`：

```java
public interface ProxyHandler {
    default void initContext(ProxyContext context) { }   // client/server addresses and both DatagramSockets
    int handleUdpClient(InetSocketAddress toAddress, byte[] packet, int length);   // sent by the client
    int handleUdpServer(InetSocketAddress fromAddress, byte[] packet, int length); // received from the server
}
```

返回值是要实际转发的字节数（可就地改 `packet` 再返回新长度）。

---

## 密钥从哪来：三类套路

netguard 只负责「把这条连接的原始字节稳定地交到你手上、并帮你转发出去」；协议本身的分帧、解密、
密钥获取是你的代码的事。按密钥来源分三类：

1. **在流里自描述。** 有些传输层混淆把密钥直接放在连接开头的头部里，或者能从头部派生出来。
   用 `getPrologue()`/`readMorePrologue()` 读够头部认出变体，`ForwardHandler` 里按同样的派生算出
   两个方向的密钥，就能解每一帧。
2. **坐在密钥交换中间现算。** 客户端用内置的服务器公钥做 DH / RSA 密钥交换时，如果能让客户端
   信任你的公钥（替换内置公钥、或客户端本身不校验），handler 就能分别和客户端、服务端各完成一次
   交换，同时拿到两边的会话密钥，解、改、再加密每一帧。不需要 hook 客户端进程。
3. **从外部拿。** 静态密钥不在流里、握手也坐不进去（如 Noise 这类双向认证握手）：用 frida 从活 App
   里把私钥 / 会话密钥导出来，交给你的 handler 或 `redirectAddress` 起的服务完成握手。媒体流（SRTP 等）
   的密钥常常在**已解密的信令**里——先把信令那条连接解开，从里面捞出密钥写盘，再喂给媒体流的解密器。

不管哪一类，解出来的帧都按 `protocol-analysis.md` 的方法验证：复用客户端自己的编解码类、用抓到的
字节做 golden fixture。

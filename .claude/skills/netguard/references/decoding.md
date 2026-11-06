# 解码：看到并改写被 MITM 的内容

被 MITM 的连接（`CONNECT_SSL` / `FILTER_H2`），解密后的内容通过 `PacketDecoder` 的回调和各种
Filter 交到你手上。`MyDecoder extends PacketDecoder`，覆写你关心的。

## PacketDecoder 构造

```java
new PacketDecoder()                           // decodePacket = true
new PacketDecoder(false)                      // ignore raw IP packets from VPN clients (no pcap, no packet-level decoding)
new PacketDecoder(new File("t.pcap"), true)   // also write raw packets to pcap; true = delete the old file first
```

`decodePacket=false` 只关掉对 VPN 原始 IP 包的处理（不写 pcap、不从原始包里解明文 TCP）。
**MITM 解密后的 HTTPS 照样解码、照样回调 `onRequest`/`onResponse`。**只想做路由时用它省点开销。

## HTTP 回调

给的是 `com.github.netguard.handler.http.HttpRequest` / `HttpResponse`（**不是** Netty 或 kraken 的；
h2 过滤器那套才是 Netty 的，见下）：

```java
@Override
protected void onRequest(HttpSession session, HttpRequest request) {
    super.onRequest(session, request);   // logs raw body + headers + params, at DEBUG only
    if ("api.example.com".equals(request.getHost())) {
        System.out.println(rawBody("request body", request.getPostData()));    // bytes as sent
        Map<String, String> query = parseParameters(request.getRequestUri());  // static helper on PacketDecoder
        // ... your parsed view, printed after the raw bytes
    }
}

@Override
protected void onResponse(HttpSession session, HttpRequest request, HttpResponse response) {
    super.onResponse(session, request, response);
    byte[] data = response.getResponseData();   // gzip already decoded; check getContentEncoding() for others
    String ct = response.getContentType();
    // ...
}
```

`HttpRequest`：`getHost()`/`getPort()`/`getScheme()`/`getRequestUri()`/`getRequestMethod()`/`getQuery()`/
`getPostData()`/`getContentType()`/`getRequestLine()`，以及公共的 `getHeader(k)`/`getHeaderKeys()`/`getHeaderString()`。
`HttpResponse`：`getResponseData()`/`getContentType()`/`getContentEncoding()`/`getTransferEncoding()`/
`getResponseCode()`/`getResponseCodeMsg()`/`getRequestVersion()`，加公共 header 方法。
其它回调：`onPollingResponse`（长轮询）、`onChunkedRequest`/`onChunkedResponse`、`onMultipartData`、
`onWebSocketHandshake`/`onWebSocketRequest`/`onWebSocketResponse`（这几个参数是 kraken 的类型）。

### 先原始字节、后解析视图

`PacketDecoder` 默认的 `onRequest`/`onResponse` **先打 body 原始字节**（文本原样、二进制走 hex+ASCII，
超过 16KB 截断），再打头和参数——但**只在 `com.github.netguard.handler.PacketDecoder` logger 是 DEBUG 时**。
自己打印时用同一个 helper：`rawBody(label, data)`（`protected static`，没有 body 返回空串）。

这不是洁癖：有服务端拿 JSON 的**空白和键序**当反爬校验，解析再序列化后这两样全没了——只看解析视图，
自己构造的请求和真机抓到的会打印得一模一样，差异无从发现。同类还有：header 大小写与顺序、multipart
的 boundary、chunked 分块边界、protobuf 字段实际排列。想要更好读的视图就在原始字节之后**另加**一段，
别替换掉原始那段。

## 更底层：解密后的原始字节流

```java
@Override public void onSSLProxyTx(InetSocketAddress c, InetSocketAddress s, byte[] data) { super.onSSLProxyTx(c, s, data); } // client -> server
@Override public void onSSLProxyRx(InetSocketAddress c, InetSocketAddress s, byte[] data) { super.onSSLProxyRx(c, s, data); } // server -> client
// Not decrypted (plain TCP): onSocketEstablish / onSocketTx / onSocketRx / onSocketFinish (default impl only logs)
```

- `onSSLProxyTx/Rx` 的 `super` 是把字节喂给 HTTP 解码器和 `SessionFactory` 的地方，**覆写必须调
  `super`**，否则 `onRequest`/`onResponse`/`Session` 全都收不到数据。
- `onSSLProxyEstablish` / `onSSLProxyFinish` 是 `final`，不能覆写。要拿主机名 / ALPN / App，用下面
  `SessionFactory` 里的 `SSLProxySession`。
- 这几个回调按到达的块给数据，**不按协议分帧**；要按帧处理用 `SessionFactory`。
- 挂了 `ForwardHandler` 的连接，这几个回调都不会被调（字节归 handler 管）。

## TLS 内的非 HTTP 二进制协议：SessionFactory + Session

跑在 TLS 里、但不是 HTTP 的专有二进制协议，用 `SessionFactory` 接管这条流的解码（只看不改；要改写用
`ForwardHandler`，见 `raw-stream.md`）：

```java
class MyDecoder extends PacketDecoder implements SessionFactory {
    MyDecoder() { setSessionFactory(this); }

    @Override
    public Session createSession(TcpSession tcp) {
        // MITM'd TLS streams arrive as SSLProxySession; return null to leave the stream alone
        if (tcp instanceof SSLProxySession) {
            String host = ((SSLSessionKey) tcp.getKey()).getHostName();
            String alpn = tcp.getSelectedApplicationProtocol();   // negotiated ALPN, may be null
            String apps = tcp.getApplication();                   // comma-separated package names / bundle ids, "" when unknown
            if ("push.example.com".equals(host)) {
                return new MySession();
            }
        }
        return null;
    }
}
```

什么流会走到这里：MITM 后**选中的 ALPN 不是 `h2` / `http/1.1`** 的 TLS 流（ALPN 为空但客户端提供了
`http/1.1` 的也算 HTTP，不会来）；以及 VPN 原始包里认不出协议的明文 TCP。

`Session`（`com.github.netguard.handler.session.Session`）三个方法，参数是 kraken 的 `Buffer`：

```java
boolean processTx(Buffer buffer) throws IOException, DecodeFailedException;   // client -> server
boolean processRx(Buffer buffer) throws IOException, DecodeFailedException;   // server -> client
void onFinish();
```

- 两个方向语义一样：框架把新到的字节追加进这个方向的缓冲，然后**只要还有未读字节就反复调你**。
  解出完整一帧就消费掉它、返回 true（接着解下一帧）；剩下的不够一帧就**把读位置退回帧头**
  （`buffer.mark()` / `buffer.reset()`）、返回 false，等下一批字节到了再调。
- 抛 `DecodeFailedException`：通过 `setSessionFactory` 挂的，**只会记一条 `decode failed` WARN，没有
  fallback**，这一批之后的字节照样继续喂进来。所以异常消息里要带够补样本的东西（帧类型、原始字节 hex）。
- 解出来的消息用复刻客户端自己的 protobuf / 编解码类（见 `protocol-analysis.md`）。

## HTTP/2 帧级过滤：Http2Filter / AbstractHttp2Filter

`FILTER_H2` 路由的连接（进管线的三个条件见 `routing.md`），挂 `getH2Filter()` 返回的过滤器。
**这里的 `HttpRequest`/`HttpResponse`/`HttpHeaders` 都是 Netty 的**（`io.netty.handler.codec.http.*`）：

```java
class MyH2Filter extends AbstractHttp2Filter {
    @Override
    public boolean filterHost(String hostName, boolean h3) {   // default returns true for every host
        return "api.example.com".equals(hostName);
    }
    @Override
    protected byte[] filterRequestInternal(HttpRequest req, HttpHeaders headers, byte[] requestData) {
        return requestData;   // return new bytes to rewrite; content-length is fixed up if present
    }
    @Override
    protected byte[] filterResponseInternal(HttpRequest req, byte[] reqData, HttpResponse resp, byte[] respData) {
        // respData is the body as sent on the wire, still content-encoded
        byte[] body = decodeContent(resp.headers().get(HttpHeaderNames.CONTENT_ENCODING), respData);
        return respData;      // return the input unchanged to observe only
    }
    @Override
    protected byte[] filterPollingResponseInternal(HttpRequest req, HttpResponse resp, byte[] respData) {
        return respData;      // long-polling / streaming responses
    }
    @Override
    public CancelResult cancelRequest(HttpRequest req, byte[] reqData, boolean polling) {
        // null = let it through; CancelResult.cancel() = reset the stream;
        // CancelResult.fake(response, body) = answer locally, nothing goes upstream
        return super.cancelRequest(req, reqData, polling);
    }
}
```

- 只想观测不改写：各 `filter*Internal` 直接返回入参。
- body 是线上原样的字节（还带着 `content-encoding`）。解开后改了内容，返回前要按原编码压回去，
  返回的字节必须和响应头里的 `content-encoding` 对得上。
- 同一个 h2 过滤器也用于 HTTP/3（`acceptUdp` 返回 `FILTER_H3`），这时 `filterHost` 的 `h3` 是 true。

## WebSocket：WebSocketFilter + WebSocketInjector

仅当连接被 TLS MITM（`CONNECT_SSL`/`FILTER_H2`）且 `filterHost` 返回 true 时生效；明文 `ws://` 不过这里。
覆写 `PacketDecoder.getWebSocketFilter()` 返回它：

```java
class MyWsFilter implements WebSocketFilter {
    private volatile WebSocketInjector injector;

    public boolean filterHost(String hostName) { return "ws.example.com".equals(hostName); }
    public void onConnected(WebSocketSession session, WebSocketInjector injector) {
        this.injector = injector;   // called once the handshake has completed; injector.isReady() is true from here
    }
    public WebSocketFrame onFrame(WebSocketSession session, boolean fromServer, WebSocketFrame frame) {
        // return the input itself = byte-exact pass-through; a new frame = replace (re-encoded); null = drop
        return frame;
    }
    public void onClosed(WebSocketSession session) { }
}
```

- 回调顺序固定：`onConnected` → 若干 `onFrame` → `onClosed`，各一次。`onConnected` 在握手完成后调用：
  HTTP/1.1 是服务端回了 `101` 之后，h2 上的 WebSocket（RFC 8441）是 `:status 200` 之后。握手没成功就
  一个回调都没有。`onClosed` 在两个方向都结束、h2 流被 RST、或整条连接断开时调用。
- `filterHost` 为 true 只影响这个主机的 WebSocket。HTTP/1.1 下按连接判断：第一个请求是 `Upgrade: websocket`
  且服务端回了 `101`，这条连接才走帧过滤；其它连接（普通请求、非 HTTP 流量）原样转发，照常进
  `onRequest`/`onResponse`。升级被服务端拒绝的那条连接也原样转发，但 `PacketDecoder` 看不到它。
  同一条 keep-alive 连接先发普通请求、后面才升级的，不会被过滤。
- `WebSocketFrame`：`getOpcode()`（`OPCODE_TEXT`/`OPCODE_BINARY`/…常量）、`isFin()`、`isText()`/`isBinary()`/
  `isControl()`、`getPayload()`（已解掩码、已解压）、`text()`；构造用 `WebSocketFrame.text(s)` / `.binary(bytes)`。
- `WebSocketInjector`：`sendToServer(frame)`/`sendToClient(frame)`，以及 `sendTextToServer`/`sendBinaryToServer`/
  `sendTextToClient`/`sendBinaryToClient`。注入帧一律未压缩发送，client→server 自动加掩码。
- `WebSocketSession`：`getHostName()`/`getClient()`/`getServer()`/`isPermessageDeflate()`/`isEstablished()`。

**注意（实战踩过）**：很多服务端对 WebSocket 很敏感——**注入帧会被直接重置连接**，**改写帧会让客户端
一直转圈**，所以除非确有必要，`onFrame` 就返回入参原样透传。

## DNS：DNSFilter

覆写 `getDNSFilter()` 返回它。`cancelDnsQuery` 在 `acceptUdp` **之前**就对每个 DNS 查询包调用：

```java
class MyDnsFilter implements DNSFilter {
    private final Inet4Address fakeAddress;

    MyDnsFilter() throws UnknownHostException {
        fakeAddress = (Inet4Address) InetAddress.getByName("192.168.31.88");
    }

    public DnsResponse cancelDnsQuery(DnsQuery q) {          // non-null = answer locally, nothing goes upstream
        if ("example.com".equals(q.getName()) && q.getType() == DnsRecord.TYPE_A) {
            DnsResponse r = q.reply();
            r.getAnswers().add(DnsRecord.a("example.com", 3600, fakeAddress));
            return r;
        }
        return null;
    }
    public DnsResponse filterDnsResponse(DnsQuery q, DnsResponse upstream) {  // may modify upstream in place
        return null;   // null = forward the upstream bytes unchanged
    }
}
```

`DnsRecord` 有 `a(...)`/`aaaa(...)`/`cname(...)` 工厂和 `TYPE_A`/`TYPE_AAAA`/`TYPE_CNAME`/`TYPE_SOA`/`TYPE_HTTPS`
常量；`DnsResponse` 有 `getAnswers()`/`getAuthorities()`/`getAdditionals()`、`setRcode(...)`
（`RCODE_NOERROR`/`RCODE_NXDOMAIN`）。

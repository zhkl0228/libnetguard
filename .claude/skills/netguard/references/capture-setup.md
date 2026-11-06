# 接入与启动

## Maven 依赖

```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>netguard</artifactId>
    <version>0.0.16</version>   <!-- check libnetguard/pom.xml for the current version -->
    <scope>test</scope>        <!-- protocol analysis usually lives in test scope -->
</dependency>
```

本机改了 libnetguard 源码后，要让使用方项目吃到新版：在 libnetguard 仓库 `mvn install`
装进本地 `~/.m2`（版本号不变也行，覆盖同版本即可），使用方重新编译即可。native 库
（`libnetguard.so` / `.dylib`）打包在 jar 里的 `natives/<平台>/` 下，随 jar 一起进 classpath，
不用单独部署。

## VpnServerBuilder 全部选项

`VpnServerBuilder.create()` 链式配置，`startServer()` 返回已启动的 `VpnServer`：

| 方法 | 作用 |
| --- | --- |
| `withPort(int)` | 监听端口（不调默认 20230）。VPN 客户端、socks/http 代理、SSL-VPN、Trojan 全复用这一个端口，按首字节自动分流 |
| `enableBroadcast(int seconds)` | 每 N 秒往 LAN 广播一次（UDP `255.255.255.255:20230`，内容 `writeUTF("vpn")`+端口），配套 VPN 客户端据此自动发现服务端。还没有客户端连上时每秒发一次 |
| `enableProxy()` | 同端口额外接受 **socks4/5 和 http/https(CONNECT) 代理**接入。不开则这两类接入被拒（SSL-VPN / Trojan 不受这个开关控制） |
| `withVpnListener(VpnListener)` | 注册监听器，见下 |
| `withReplayLogFile(File)` | 把每条连接的收发字节记成 JSON 行，重启后重放（调试解码器时不用反复真连）。**只在 `BaseVpnListener` 下生效**，见下 |
| `enablePreMasterSecretsLogFile()` / `(File)` | 通过 javaagent 把**本 JVM**（代理连上游那条腿）的 pre-master secret 落盘（默认 `target/pre_master_secrets.log`），好让 Wireshark 解开 pcap 里那段密文。启动时打印要加的 `-javaagent:` 参数 |
| `enableTransparentProxying()` / `(int port)` | macOS pf 透明代理接入（见仓库 `osx_pf/`，无参默认端口 20238）。**一般不用**——VPN 接入隔离更精准，且透明代理拿不到 App 身份 |
| `disableNetGuard()` | 关掉 native 核心，纯 Java 路径。调试用 |

只想快速起一个：`VpnServer.createSimpleBuilder(port, decoder)` 返回已配好 `enableBroadcast(10)` 和
`BaseVpnListener` 的 builder，可以接着链。

启动后 `vpnServer.waitShutdown()` 阻塞读 stdin，输入 `q` / `exit` 调 `shutdown()` 停；
`shutdown()` 关 socket、停所有客户端、join 线程，**重复调用会抛 `IllegalStateException`**。

## 两种 VpnListener 写法

**首选 `BaseVpnListener`**（支持 replay）：

```java
.withVpnListener(new BaseVpnListener() {
    @Override
    protected IPacketCapture createPacketCapture() {
        return new MyDecoder();   // called once from the constructor
    }
})
```

- `createPacketCapture()` 是**在 `BaseVpnListener` 构造器里调的，只调一次**。之后每个客户端连上，
  `onConnectClient`（`final`）都把**同一个** capture 挂上去。所以一个 decoder 实例要同时服务所有客户端、
  所有连接，回调来自多个线程，里面的状态要线程安全。
- 也因为是在父类构造器里调的：匿名子类自己声明的字段这时**还没初始化**（是 null）。decoder 需要的
  依赖在外面建好、以局部变量传进来。
- replay 通过 `initializeReplay(replay)` → `packetCapture.replay(replay)` 接上；replay 失败只记 WARN。

**lambda 写法**（无 replay）：

```java
.withVpnListener(vpn -> {
    vpn.setPacketCapture(new MyDecoder());   // one decoder per client
    vpn.setConnectionListener(myListener);   // optional
    vpn.setDirectAllowAll();                 // optional: pass everything through, observe only
})
```

注意：`VpnListener.initializeReplay` 的默认实现抛 `UnsupportedOperationException`，
所以**用了 `withReplayLogFile` 就必须用 `BaseVpnListener`**，否则 `startServer()` 时就抛。

`Vpn` 接口可用方法：`getClientOS()`、`getRemoteSocketAddress()`、`setPacketCapture()`、
`setConnectionListener()`、`setDirectAllowAll()`。`ClientOS` 枚举：`Android`/`iOS`/`MacOS`/`Windows`
（VPN 客户端）、`SocksV4`/`SocksV5`/`HttpProxy`/`HttpsProxy`/`TrojanProxy`（代理接入）、
`TransparentProxying`、`SSLVpn`/`QianxinVPN`、`Fallback`。

## 装根证书（解 HTTPS 的前提）

MITM 解 HTTPS，设备得先信任本服务端的根证书。**连上接入层之后**用设备浏览器打开：

```
http://88.88.88.88:88
```

这是个只在隧道里可达的假地址，到它的连接都被直接应答成根证书本身
（`application/x-pem-file`，带 `Content-Disposition`，浏览器当文件下载 `NetGuard.pem`）。
装完**手动打开信任开关**：iOS 在「设置 → 通用 → 关于本机 → 证书信任设置」；Android 装到
「用户凭据」。只装不信任不生效。

代码里要拿根证书 PEM：`RootCert.load().pem`（根证书和私钥来自 jar 里打包的
`charles-ssl-proxying.p12`）。可以自己起个 endpoint 发它。

**这张根证书的私钥随 jar 公开分发**，任何拿到这个库的人都能用它签证书。只在测试设备上信任它，
用完把信任关掉，别装在日常用的设备上。

不装证书也能跑：TCP / UDP / DNS 照常抓，只是 HTTPS 那部分（`CONNECT_SSL` / `FILTER_H2`）解不开。

## JDK / JVM 参数

- 需要 JDK 11+（libnetguard 本身 `source/target 11`）。
- JDK 9 以上跑要加：
  `--add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED`
  （视使用方依赖，有时还要 `--add-opens=java.base/java.lang=ALL-UNNAMED`）。
- 用 Chrome 测 HTTP/3 时：`--origin-to-force-quic-on=http3.is:443`。

## 输出去向

- pcap：`new PacketDecoder(new File("target/x.pcap"), true)` 构造时落盘（第二个参数 true = 先删旧文件），
  或在子类里调 `setOutputPcapFile(file)`。配合 `enablePreMasterSecretsLogFile()` 可让 Wireshark 解密其中的 TLS。
- 可读分析：你在回调里 `System.out` / SLF4J 打的东西。`PacketDecoder` 自带的输出（含原始 body）
  要把 `com.github.netguard.handler.PacketDecoder` logger 开到 DEBUG 才出。
- replay：`withReplayLogFile` 指定的文件（JSON 行）。

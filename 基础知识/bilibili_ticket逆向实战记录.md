# B站 x-bili-ticket 从零逆向实战记录

> **前置文档**：
> - [bilibili_自动评论脚本技术沉淀.md](./bilibili_自动评论脚本技术沉淀.md) — JWT 基础知识 + 开源方案
> - [bilibili_评论接口完整逆向记录.md](./bilibili_评论接口完整逆向记录.md) — 抓包发现 x-bili-ticket header
>
> **日期**：2026-02-20
> **工具**：Frida 17.7.3 + jadx（静态反编译）
> **目标**：不依赖开源文档，纯靠逆向找到 x-bili-ticket 的获取方式

---

## 一、起点：我们知道什么

从之前的抓包中，我们知道：
- 评论接口的 header 里有 `x-bili-ticket`，值是 JWT 格式
- JWT 解码后有 `exp`（过期时间）和 `buvid`（设备标识）
- JWT 会过期（约 8 小时），不能硬编码

**核心问题**：App 是怎么获取这个 JWT 的？

---

## 二、思路分析

JWT 来源只有三种可能：写死 / 本地生成 / 服务端下发。

通过 JWT 基础知识判断：
- `HS256` 签名 → 如果密钥在本地，反编译就能伪造，不合理
- `iat` 是最近的时间 → 不是写死的
- **结论：服务端下发**

既然是服务端下发，就需要找到获取接口。但 App 已经登录，有缓存的 JWT，不会重新请求。
所以**抓包抓不到** → 必须用 **Frida hook** 从代码层面追踪。

---

## 三、Frida 动态追踪过程

### 3.1 第一次尝试：Hook SharedPreferences（失败）

**思路**：JWT 缓存在本地，App 每次用都要读，hook SP 的 getString 就能抓到。

写了 `trace_ticket.js`，hook `SharedPreferencesImpl.getString` 和 `putString`，
过滤 `value.startsWith("eyJ")`（JWT 固定前缀）。

> **为什么 `eyJ` 是 JWT 特征？**
> JWT 格式为 `Base64(Header).Base64(Payload).Base64(Signature)`，
> 而 Header 几乎都以 `{"` 开头（如 `{"alg":"HS256",...}`）。
> `{"` 的字节是 `0x7B 0x22`，Base64 编码后恰好是 `eyJ`。
> 因此**几乎所有 JWT 都以 `eyJ` 开头**，可作为快速过滤的可靠特征。

**踩坑 1**：第一版同时 hook 了 `HashMap.put`，App 启动直接崩溃。
- 原因：HashMap.put 每秒调用百万次，hook 开销太大
- 解决：去掉 HashMap.put hook

**踩坑 2**：hook 在 App 启动时立即执行，与反检测库 `libmsaoaidsec.so` 冲突导致 `Process terminated`。
- 解决：用 `setTimeout(fn, 5000)` 延迟 5 秒再挂载 hook

**结果**：App 正常启动了，但 **没有任何 JWT 输出**。

```
[trace_ticket] Hook 已就绪（SP getString + putString）
[trace_ticket] 现在进入任意视频页面触发请求即可
（进入视频页... 无任何 eyJ 输出）
```

**结论**：B站不用 SharedPreferences 存储 ticket。

> **心路历程**：SP hook 是逆向中最常见的第一手段——Android App 的配置/缓存大部分存在
> SharedPreferences 里，hook getString 就能监控所有读取。但 B站 ticket 不在 SP 中，
> 这说明 App 用了其他存储方式（可能是内存缓存、数据库、或自定义存储）。
> SP hook 失败不代表思路错误，而是说明需要换一个切入点。
> 逆向的核心方法论：**一条路走不通就换方向，从存储层找不到就从使用层找**。

### 3.2 搜索 MMKV（失败）

**思路**：SP 不行，那试试 MMKV。中国 App 常用腾讯的 MMKV 替代 SP（性能更好）。

```javascript
Java.enumerateLoadedClasses({
    onMatch: function(name) {
        if (name.toLowerCase().indexOf("mmkv") !== -1) console.log(name);
    },
    onComplete: function() { console.log("[done]"); }
});
// 输出：[done]  ← 没有 MMKV 相关类
```

**结论**：B站也没用 MMKV。

> **心路历程**：两条存储层的路都走不通（SP ✗、MMKV ✗），说明 B站 ticket
> 的存储方式比较特殊。此时需要**转变思路**：与其纠结"数据存在哪里"，
> 不如直接找"谁在使用这个数据"。我们知道每次网络请求都带 ticket header，
> 那么一定有某个类/方法负责提供 ticket 值。直接搜类名，从使用方入手。

### 3.3 换思路：搜索 ticket 相关类名（突破口）

既然存储层摸不到，换个方向 —— 直接在内存中搜索包含 "ticket" 的类：

```javascript
Java.enumerateLoadedClasses({
    onMatch: function(name) {
        if (name.toLowerCase().indexOf("ticket") !== -1) console.log("[class] " + name);
    },
    onComplete: function() { console.log("[done]"); }
});
```

**结果**：

```
[class] com.bilibili.gripper.container.network.producer.TicketProducerKt$producerTicket$Lambda
[class] com.bilibili.lib.rpc.ticket.Ticket
[class] com.bilibili.gripper.moss.TicketImpl$Lambda
[class] com.bilibili.app.producers.auth.ExchangeTicketServiceProvider$asProvider$Lambda
[class] kntr.base.net.comm.imp.InitGTicketKt
[class] com.bilibili.lib.ticket.api.BiliTickets
```

**分析**：`BiliTickets` 看起来是核心类，名字最直接。

### 3.4 查看 BiliTickets 的方法

```javascript
var cls = Java.use("com.bilibili.lib.ticket.api.BiliTickets");
cls.class.getDeclaredMethods().forEach(function(m) { console.log("  " + m); });
```

**结果**：

```
getTicketSyncWRetry()     ← 同步获取 ticket（带重试）
init()                     ← 初始化
maybeGetTicket()           ← 检查是否需要刷新
onTicketReq(String, String) → String   ← 请求时获取 ticket
onTicketResp(NetworkEvent)             ← 响应回调
```

**分析**：`onTicketReq` 最关键 —— 每次发请求时调用，返回 ticket 字符串。

### 3.5 Hook BiliTickets 三个关键方法

```javascript
BT.onTicketReq.implementation = function(arg1, arg2) {
    console.log("│ arg1 = " + arg1);    // host
    console.log("│ arg2 = " + arg2);    // path
    var result = this.onTicketReq(arg1, arg2);
    console.log("│ return = " + result); // JWT!
    return result;
};
```

**结果**（进入视频页后）：

```
┌─── [onTicketReq] 发起 ticket 请求 ───
│ arg1 = cm.bilibili.com
│ arg2 = /cm/api/fees/wise
│ return = eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9...
└──────────────────────────────────────
```

**发现**：`onTicketReq(host, path)` 直接返回了缓存的 JWT。每次 App 发网络请求都会调它拿 ticket。

### 3.6 查找 ticket 存储位置（一波三折）

**尝试 1**：查看 BiliTickets 的字段

```javascript
Java.choose("com.bilibili.lib.ticket.api.BiliTickets", {
    onMatch: function(instance) { /* 遍历字段 */ }
});
// 结果：只有一个 INSTANCE 字段（Kotlin 单例），没有存储 ticket 的字段
```

**尝试 2**：查看父类字段 → Object 基类，没有额外字段

**尝试 3**：搜索 Kotlin 生成的伴生类

```javascript
var candidates = ["BiliTicketsKt", "TicketStore", "TicketManager"];
// 全部找不到
```

**尝试 4**：查看 ticket 包下所有类

```javascript
// 搜索 com.bilibili.lib.ticket 包
// 结果：整个包只有 BiliTickets 一个类！
```

**困境**：`BiliTickets` 没有字段，没有伴生类，整个包只有它一个类，
但 `onTicketReq` 能返回 ticket —— ticket 一定是通过**外部依赖注入**进来的。

**心路历程**：到这里纯 Frida 动态追踪的效率已经很低了。
盲目搜索内存中的对象不现实（类太多），需要**切换工具**。

---

## 四、jadx 静态分析（突破）

### 4.1 工具切换的决策

Frida 的优势是动态观察运行时行为，但看不到代码逻辑。
jadx 能直接看反编译的源码，适合追踪内部调用链。

**逆向经验**：Frida 和 jadx 要配合用，单靠一个很容易卡住。

### 4.2 在 jadx 中搜索 onTicketReq

搜索结果列出了调用链：

```
com.bilibili.gripper.moss.j.onTicketReq          ← 中间代理
com.bilibili.gripper.container.network.producer.g.a.a()   ← 返回 ticket
com.bilibili.gripper.container.network.producer.g.a.update() ← 刷新 ticket
```

### 4.3 层层剥开

**第一层：`com.bilibili.gripper.moss.j`**

```java
public String onTicketReq(String str, String str2) {
    return BiliTickets.INSTANCE.onTicketReq(str, str2);  // 纯转发
}
```

只是个壳，直接调 BiliTickets。

**第二层：`com.bilibili.lib.ticket.api.BiliTickets`**

```java
public String onTicketReq(String str, String str2) {
    return b.f434431a.i();  // 委托给 vw2.b 类
}

public final void getTicketSyncWRetry() {
    b.f434431a.e();  // 刷新也委托给 vw2.b
}
```

所有方法都委托给 **`vw2.b`** 这个混淆类。BiliTickets 本身只是个门面。

**第三层：`vw2.b`** —— **核心管理类！**

```java
// i() 方法 —— 读取 ticket
public final String i() {
    xw2.b bVarA = xw2.a.f445391a.a();   // 从存储取 ticket 对象
    String strA = bVarA.a();              // 取 ticket 字符串
    boolean zC = bx2.b.c(bx2.b.b(), bVarA.b());  // 检查是否过期
    if (zC) {
        h();  // 过期 → 触发异步刷新
    }
    return strA;
}

// e() 方法 —— 实际刷新 ticket
public final void e() {
    GetTicketResponse resp = yw2.a.f450225a.c();  // ← 网络请求！
    xw2.a.f445391a.b(new xw2.b(resp.getTicket(), expiry));  // 存储新 ticket
}

// j() 方法 —— 服务端通知过期
public final void j(NetworkEvent event) {
    if (event.getHeader().getTicketStatus() == "1") {  // 服务端说过期了
        h();  // 触发刷新
    }
}
```

**关键发现**：
- ticket 存储在 `xw2.a.f445391a` → `xw2.b{ticket字符串, 过期时间}`
- 刷新通过 `yw2.a.f450225a.c()` 发起网络请求
- 返回类型是 `com.bapis.bilibili.api.ticket.v1.GetTicketResponse` → **gRPC protobuf！**

**第四层：`yw2.a`** —— 网络请求（带重试）

```java
// c() —— 带重试的获取（默认 4 次）
public final GetTicketResponse c() {
    int retryLimit = 4;
    for (int i = 1; i <= retryLimit; i++) {
        try {
            long backoff = a(retryCount);  // 退避等待
            if (backoff > 0) Thread.sleep(backoff);
            GetTicketResponse resp = b();  // 实际调用
            retryCount = 0;
            return resp;
        } catch (Throwable e) {
            retryCount++;
        }
    }
    return null;
}

// b() —— 实际 gRPC 调用
private final GetTicketResponse b() {
    return new TicketMoss(null, 0, null, 7, null)
        .executeGetTicket(zw2.a.a());  // ← gRPC 调用
}
```

**第五层：`zw2.a`** —— 请求参数构造

```java
public static final GetTicketRequest a() {
    GetTicketRequest.Builder builder = GetTicketRequest.newBuilder();
    builder.setKeyId("ec01");  // ← key_id 确认是 "ec01"

    // context 字段
    builder.putContext("x-fingerprint", BiliIds.getFpMaterialInPb());  // 设备指纹
    builder.putContext("x-exbadbasket", LibBili.dp(flag));             // 风控数据（native）

    // 签名 —— native 函数！
    builder.setSign(ByteString.copyFrom(
        LibBili.st(nr2.a.f367438a.a(), contextMap, "ec01")  // ← LibBili.st()
    ));

    return builder.build();
}
```

---

## 五、完整调用链总结

```
用户进入视频页，App 发起网络请求
  │
  ├─ BiliTickets.onTicketReq(host, path)          [门面类]
  │   └─ vw2.b.i()                                [核心管理]
  │       ├─ xw2.a.f445391a.a() → xw2.b           [存储层：读取 ticket]
  │       │   ├─ .a() → ticket 字符串
  │       │   └─ .b() → 过期时间
  │       ├─ bx2.b.c() 检查是否过期
  │       │   └─ 过期 → h() 触发异步刷新
  │       └─ return ticket 字符串
  │
  ├─ [异步刷新流程]
  │   └─ vw2.b.h()                                [刷新入口，加锁]
  │       └─ vw2.b.c() → 提交到线程池
  │           └─ vw2.b.e()                        [实际刷新]
  │               └─ yw2.a.c()                    [带重试，4次]
  │                   └─ yw2.a.b()                [网络调用]
  │                       └─ TicketMoss.executeGetTicket(request)  [gRPC]
  │                           ├─ 请求参数（zw2.a.a()）：
  │                           │   ├─ key_id = "ec01"
  │                           │   ├─ context["x-fingerprint"] = 设备指纹
  │                           │   ├─ context["x-exbadbasket"] = 风控数据
  │                           │   └─ sign = LibBili.st(timestamp, context, "ec01")
  │                           └─ 响应：GetTicketResponse{ticket, ttl}
  │               └─ xw2.a.f445391a.b(xw2.b(ticket, expiry))  [存储新 ticket]
  │
  └─ BiliTickets.onTicketResp(NetworkEvent)       [响应回调]
      └─ vw2.b.j()
          └─ 如果 ticketStatus=="1" → h() 强制刷新
```

---

## 六、关键逆向发现

### 6.1 存储机制

ticket **不存在 SharedPreferences 也不在 MMKV**，而是存在 Java 内存对象中：
- `xw2.a` 是存储管理器（单例）
- `xw2.b` 是数据对象，持有 `{ticket字符串, 过期时间戳}`
- 使用 `ReentrantReadWriteLock` 保证线程安全

### 6.2 获取协议

App 内部使用 **gRPC** 而非 REST：
- 服务：`bilibili.api.ticket.v1.Ticket/GetTicket`
- 编码：Protocol Buffers
- 客户端：`TicketMoss` 类

### 6.3 请求签名

签名通过 **native 函数** `LibBili.st()` 计算：
```java
LibBili.st(
    nr2.a.f367438a.a(),   // 第一个参数：待确认（可能是时间戳）
    linkedHashMap,         // 第二个参数：context 数据（指纹 + 风控）
    "ec01"                 // 第三个参数：key_id
)
```

这个 native 函数在 `libbili.so` 中，需要进一步逆向。

### 6.4 与 REST 版本的对比

| 项目 | App gRPC 版本（自己逆向） | REST 版本（开源文档） |
|------|-------------------------|---------------------|
| 协议 | gRPC protobuf | HTTP POST |
| key_id | `ec01` | `ec01` / `ec02` |
| 签名 | `LibBili.st()` native | HMAC-SHA256("Ezlc3tgtl") |
| 额外数据 | 指纹 + 风控 | 无 |
| 复杂度 | 高（需逆 so） | 低（纯 Python） |
| 结果 | 同一个 JWT | 同一个 JWT |

---

## 七、踩坑记录

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| HashMap.put hook 导致 App 崩溃 | 每秒百万次调用，开销太大 | 去掉该 hook |
| SP hook 导致 Process terminated | 与反检测库 libmsaoaidsec.so 冲突 | setTimeout 延迟 5 秒 |
| SP hook 无输出 | B站不用 SP 存 ticket | 换思路搜类名 |
| Lambda 类找不到 | Kotlin lambda 运行时类名特殊 | 用 enumerateLoadedClasses 搜索 |
| BiliTickets 无字段 | 纯门面类，委托给混淆类 | jadx 静态分析看实际代码 |
| jadx 混淆名 vs 运行时名 | ProGuard 混淆映射不一致 | 需要两边对照 |

---

## 八、方法论总结

### 工具配合

```
Frida（动态）                    jadx（静态）
  ├─ 搜索类名                     ├─ 看代码逻辑
  ├─ hook 方法观察输入输出          ├─ 追踪调用链
  ├─ 读取实例字段值                 ├─ 还原混淆类关系
  └─ 验证运行时行为                 └─ 找到 native 函数入口
```

**关键经验**：
1. **先动态再静态**：Frida 快速定位关键类，jadx 深入看逻辑
2. **搜类名是突破口**：`enumerateLoadedClasses` + 关键词过滤
3. **卡住就换工具**：Frida 看不到内部逻辑时，切 jadx
4. **门面模式很常见**：公开类往往只是壳，真正逻辑在混淆的内部类里

### 逆向路线回顾

```
SP hook（失败）→ MMKV 搜索（失败）→ 类名搜索（突破）
  → Frida hook BiliTickets（找到入口）
  → 查字段（没有）→ jadx 看代码（突破）
  → 逐层追踪：BiliTickets → vw2.b → yw2.a → zw2.a
  → 找到 gRPC 调用 + LibBili.st() native 签名
```

---

## 九、逆向 LibBili.st()（SO 层 — 动静结合）

> 之前逆向 sign 算法时已完整分析过 libbili.so（见 [bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md)），
> 本次复用同一套方法论：RegisterNatives 定位 → Ghidra 读逻辑 → Frida 填常量。

### 9.1 确认 st() 的 Java 层签名

首先需要知道 `LibBili.st()` 的准确参数类型。用 Frida 枚举 LibBili 所有方法：

```javascript
Java.perform(function() {
    var LB = Java.use("com.bilibili.nativelibrary.LibBili");
    LB.class.getDeclaredMethods().forEach(function(m) { console.log("  " + m); });
});
```

**输出（关键部分）**：

```
public static byte[] com.bilibili.nativelibrary.LibBili.st(byte[],java.util.Map,java.lang.String)
static native byte[] com.bilibili.nativelibrary.LibBili.st(byte[],java.util.SortedMap,java.lang.String)
```

**发现**：第一个参数不是 SortedMap，而是 **`byte[]`**！jadx 中看到的 `nr2.a.f367438a.a()` 返回的是字节数组。

两个重载：
- `public static st(byte[], Map, String)` — 公开包装（Map → TreeMap 转换）
- `static native st(byte[], SortedMap, String)` — 实际 native 方法

### 9.2 探查第一个参数 nr2.a 的内容

`nr2.a` 是 Kotlin 单例，有一个 `a()` 方法返回 `byte[]`。通过反射读取：

```javascript
Java.perform(function() {
    var nr2a = Java.use("nr2.a");
    var field = nr2a.class.getDeclaredField("a");
    field.setAccessible(true);
    var inst = Java.cast(field.get(null), nr2a);
    var realBytes = inst.a();
    // 输出 hex 和 UTF-8
});
```

**输出**：

```
length = 332
utf8 = ···XU851958B8BC3412258E291F5D3152432F1CA"android*android:html5_search_google
BXiaomiJMI 9R13Z@0fcca6e89ccb4cb6b3444f3fbf2d5c78...j8.83.0r@0fcca6e89ccb...
```

**分析**：这是 **Protobuf 编码**的设备信息！可以识别出：

| 字段 | 值 |
|------|-----|
| buvid | `XU851958B8BC3412258E291F5D3152432F1CA` |
| platform | `android` |
| mobi_app | `android` |
| channel | `html5_search_google` |
| brand | `Xiaomi` |
| model | `MI 9` |
| os_ver | `13` |
| app_ver | `8.83.0` |
| fingerprint hash | `0fcca6e89ccb4cb6b...`（重复 3 次） |

gRPC 用 protobuf 编码，所以第一个参数是序列化后的设备上下文。

### 9.3 用 RegisterNatives 找到 st() 在 libbili.so 的偏移

复用 sign 逆向时的 `hook_sign.js`，hook `art::ClassLinker::RegisterNative` 捕获所有 native 方法注册：

```bash
frida -U -f tv.danmaku.bili -l bypass.js -l hook_sign.js
```

**输出**：

```
[+] libbili.so native 方法注册: fnPtr=0x74fb711030 offset=+0x9030
[+] libbili.so native 方法注册: fnPtr=0x74fb711038 offset=+0x9038
[+] libbili.so native 方法注册: fnPtr=0x74fb711048 offset=+0x9048
[+] libbili.so native 方法注册: fnPtr=0x74fb711050 offset=+0x9050   ← 已知是 s()（sign）
[+] libbili.so native 方法注册: fnPtr=0x74fb711058 offset=+0x9058
[+] libbili.so native 方法注册: fnPtr=0x74fb711068 offset=+0x9068
[+] libbili.so native 方法注册: fnPtr=0x74fb711074 offset=+0x9074
[+] libbili.so native 方法注册: fnPtr=0x74fb711078 offset=+0x9078
[+] libbili.so native 方法注册: fnPtr=0x74fb711080 offset=+0x9080
[+] libbili.so native 方法注册: fnPtr=0x74fb711228 offset=+0x9228
[+] libbili.so native 方法注册: fnPtr=0x74fb711230 offset=+0x9230
```

11 个 native 方法全部捕获。

### 9.4 快速锁定 st() 的偏移

sign 逆向时，我们去 Ghidra 逐个检查参数类型来确认函数。这次用更快的方法——
**直接在 Frida 中手动调用 st()，看哪个方法编号被触发**：

```javascript
Java.perform(function() {
    var LibBili = Java.use("com.bilibili.nativelibrary.LibBili");
    var arr = Java.array('byte', [0x01, 0x02]);
    var HashMap = Java.use("java.util.HashMap");
    var map = HashMap.$new();
    map.put("ts", "1740000000");
    try { LibBili.st(arr, map, "ec01"); } catch(e) {}
});
```

**输出**：

```
>>> 方法 #10 被调用! addr=0x74fb711230 offset=+0x9230
```

**结论**：`LibBili.st()` = **方法 #10，偏移 +0x9230，Ghidra 地址 `0x109230`**

> **技巧总结**：之前 sign 只能靠 Ghidra 交叉验证（因为 `s()` 每次请求都触发，无法排除法），
> 而 `st()` 不会主动触发（ticket 已缓存），反而可以用「手动调用 + 观察方法编号」快速定位。

---

## 十、Ghidra 静态分析 st() 调用链

### 10.1 入口函数 FUN_00109230（JNI 入口，OLLVM 壳）

```c
// Ghidra 地址 0x109230，JNI 签名：(JNIEnv*, jclass, jbyteArray, jobject, jstring)
void FUN_00109230(env, jclass, param_3, param_4, param_5) {
    // OLLVM 状态机骨架... 剥掉后实际只有一行：
    return FUN_001a5474(env, param_3, param_4, param_5);
    //                       ↑byte[]    ↑Map     ↑String
}
```

与 sign 的入口（FUN_00109050）完全同一模式：JNI 入口 → 透传到内部函数，`jclass` 被丢弃（静态方法标准做法）。

### 10.2 核心函数 FUN_001a5474（OLLVM 重灾区）

这个函数有 200+ 行 OLLVM 状态机代码。通过识别 JNI vtable 偏移还原出真实逻辑：

**JNI vtable 偏移对照表**：

| 代码中的偏移 | vtable 索引 | JNI 函数 |
|-------------|------------|----------|
| `*param_1 + 0x558` | 171 | `GetArrayLength` |
| `*param_1 + 0x580` | 176 | `NewByteArray` |
| `*param_1 + 0x640` | 200 | `GetByteArrayRegion` |
| `*param_1 + 0x680` | 208 | `SetByteArrayRegion` |

> **分析方法**：JNIEnv* 是函数表指针的指针。`offset / 8 = 索引`（arm64 每指针 8 字节），
> 然后对照 JNI 规范的函数列表。这是 SO 逆向中非常实用的技能。

**还原后的伪代码**：

```c
byte[] FUN_001a5474(JNIEnv* env, jbyteArray protobuf, jobject sortedMap, jstring keyIdStr) {
    // 1. 空参数检查（null → 抛 Java 异常并返回 null）
    if (!protobuf || !sortedMap || !keyIdStr) {
        throwException(env, ...);
        return null;
    }

    // 2. 获取 protobuf 字节数组长度
    int pb_len = GetArrayLength(env, protobuf);            // JNI 0x558

    // 3. 序列化 SortedMap 为 byte[]
    jbyteArray mapBytes = FUN_001a606c(env, sortedMap);    // Map → byte[]
    int map_len = GetArrayLength(env, mapBytes);           // JNI 0x558

    // 4. 拼接两段数据: protobuf + mapBytes
    int total_len = pb_len + map_len;
    byte buffer[total_len];  // 栈上分配
    GetByteArrayRegion(env, protobuf, 0, pb_len, buffer);             // JNI 0x640
    GetByteArrayRegion(env, mapBytes, 0, map_len, buffer + pb_len);   // JNI 0x640

    // 5. 获取 key_id 字符串 → 查表得到真正的 HMAC 密钥
    char* key = FUN_001a6a80(env, keyIdStr);   // "ec01" → "Ezlc3tgtl"
    int key_len = strlen(key);

    // 6. HMAC 签名
    byte output[256] = {0};
    int out_len = 0;
    FUN_001a6bc8(buffer, total_len, key, key_len, output, &out_len);  // 核心签名

    // 7. 包装为 Java byte[] 返回
    jbyteArray result = NewByteArray(env, out_len);                   // JNI 0x580
    SetByteArrayRegion(env, result, 0, out_len, output);              // JNI 0x680
    return result;
}
```

**心路历程**：面对 200 行 OLLVM 状态机，关键不是逐行理解每个状态跳转，
而是**抓住 JNI 调用**（vtable 偏移固定、语义明确）和**子函数调用**作为骨架，
忽略 `x.9`、`y.10` 等不透明谓词和状态变量 `iVar4`/`iVar10` 的值流。

### 10.3 HMAC 签名函数 FUN_001a6bc8（可读性最好）

```c
// Ghidra 地址 0x1a6bc8，文件偏移 0xa6bc8
int FUN_001a6bc8(byte* data, int data_len, char* key, int key_len,
                 byte* output, int* out_len) {
    byte ctx[240] = {0};                      // HMAC-SHA256 上下文

    FUN_00164fc0(ctx, key, key_len);          // HMAC_Init：设置密钥
    FUN_001658a4(ctx);                        // ipad/opad XOR 处理
    FUN_00165ab8(ctx, data, data_len);        // HMAC_Update：输入数据
    FUN_00165b94(output, 0x20, ctx);          // HMAC_Final：输出摘要

    *out_len = 0x20;                          // 固定 32 字节输出
    return 0;
}
```

**关键发现**：
- 输出长度 `0x20 = 32` 字节 → **SHA-256**
- 4 步标准 HMAC 流程（Init → Pad → Update → Final）
- 上下文 240 字节（`0xf0`），容纳内外两个 SHA-256 context + 密钥材料

### 10.4 HMAC Init 函数 FUN_00164fc0（密钥处理）

```c
// Ghidra 地址 0x164fc0
int hmac_init(hmac_ctx* ctx, char* key, uint key_len) {
    if (key_len <= 0x40) {
        // key <= 64 字节（SHA-256 block size）：直接存储
        memcpy(ctx + 0x70, key, key_len);
    } else {
        // key > 64 字节：先 SHA256(key) 缩短为 32 字节
        SHA256_Init(ctx);
        SHA256_Update(ctx, key, key_len);
        SHA256_Final(ctx + 0x90, ctx);
        memcpy(ctx + 0x70, ctx + 0x90, 0x20);
    }
    return 1;
}
```

这是标准 HMAC 密钥预处理：
- key ≤ block_size(64) → 直接使用（右侧补零）
- key > block_size → 先 hash 成 32 字节再使用

我们的 key `"Ezlc3tgtl"` 只有 9 字节 < 64，走第一个分支。

---

## 十一、Frida 动态验证（填常量）

静态分析得出算法结构是 HMAC-SHA256，但有两个关键问题需要动态确认：
1. key 是 `"ec01"` 本身还是查表得到的？
2. 实际输入输出是什么样的？

### 11.1 Hook HMAC 核心函数

编写 `hook_st_native.js`，用纯 Native Interceptor hook `FUN_001a6bc8`（偏移 `0xa6bc8`）：

```javascript
var mod = Process.findModuleByName("libbili.so");
Interceptor.attach(mod.base.add(0xa6bc8), {
    onEnter: function(args) {
        this.key = args[2];
        this.key_len = args[3].toInt32();
        this.data_len = args[1].toInt32();
        console.log("key_len = " + this.key_len);
        console.log("key_str = " + this.key.readUtf8String(this.key_len));
        console.log("data_len = " + this.data_len);
    },
    onLeave: function(retval) {
        // 读取 32 字节输出...
    }
});
```

然后手动触发 `LibBili.st()` 调用。

**输出**：

```
┌─── [HMAC] FUN_001a6bc8 ───
│ key_len = 9
│ key_hex = 457a6c63337467746c
│ key_str = Ezlc3tgtl
│ data_len = 332
│ data_hex = 080110a4fc9a041a255855383531393538423842433334313232...
│ out_len = 32
│ output  = 233e08387a07d01b34c0496aa56ff21c176bc453aa888757a6233769196ae48a
└────────────────────────────
```

**重大发现**：HMAC 密钥不是 `"ec01"`，而是 **`"Ezlc3tgtl"`**！

### 11.2 定位密钥查找函数

静态分析中，`FUN_001a6a80(env, keyIdStr)` 被当作 `GetStringUTFChars`。
但动态验证表明它**把 key_id 映射为了真正的密钥**。

追加 hook `FUN_001a6a80`（偏移 `0xa6a80`）验证：

```javascript
Interceptor.attach(mod.base.add(0xa6a80), {
    onLeave: function(retval) {
        console.log("[FUN_1a6a80] return = " + retval.readUtf8String());
    }
});
```

**输出**：

```
[FUN_1a6a80] return = Ezlc3tgtl
```

**确认**：`FUN_001a6a80` 就是密钥查找函数。它接收 jstring `"ec01"`，内部查表后返回 `"Ezlc3tgtl"`。
查找表大概率被 `datadiv_decode` 加密存储在 `.so` 中（与 sign 逆向中发现的 appSecret 存储方式一致）。

---

## 十二、完整算法还原

### 12.1 LibBili.st() 的完整流程

```
LibBili.st(byte[] protobuf, Map context, String keyId)

Step 1: 拼接数据
  data = protobuf_device_info + serialize(context_map)

Step 2: 查找密钥
  "ec01" → FUN_001a6a80() 查表 → "Ezlc3tgtl"

Step 3: HMAC-SHA256 签名
  sign = HMAC-SHA256(key="Ezlc3tgtl", data=combined_bytes)

Step 4: 返回 32 字节签名
```

### 12.2 与 REST 版本的最终对比

| 项目 | Native gRPC 版本（本次逆向） | REST 版本（开源文档） |
|------|---------------------------|---------------------|
| 签名算法 | HMAC-SHA256 | HMAC-SHA256 |
| **密钥** | **`Ezlc3tgtl`** | **`Ezlc3tgtl`** |
| key_id | `"ec01"`（查表得到密钥） | `"ec01"`（作为参数传递） |
| 输入数据 | protobuf 设备信息 + Map context | `"ts" + timestamp` 字符串 |
| 输出 | 32 字节 raw bytes | 64 字符 hex 字符串 |
| 复杂度 | 高（protobuf + native） | 低（纯字符串拼接） |

**核心结论**：Native 版和 REST 版**使用同一个 HMAC 密钥**。
区别只在于数据编码方式（protobuf vs 字符串）和传输协议（gRPC vs REST）。
我们的 `bili_ticket.py` REST 实现完全正确。

### 12.3 调用链全景图

```
【Java 层】
LibBili.st(protobufBytes, map, "ec01")
  │  public static byte[] st(byte[], Map, String)
  │  └─ 内部转 TreeMap，调 native 版本
  │
  ↓ JNI 调用

【Native 层 — libbili.so】

FUN_00109230 (offset +0x9230, JNI 入口)
  │  OLLVM 状态机壳，透传参数
  ↓
FUN_001a5474 (核心逻辑，200+ 行 OLLVM)
  ├─ GetArrayLength(protobuf)                    [JNI 0x558]
  ├─ FUN_001a606c(env, sortedMap) → mapBytes     [Map 序列化为 byte[]]
  ├─ GetByteArrayRegion × 2                      [JNI 0x640，拼接数据]
  ├─ FUN_001a6a80(env, "ec01") → "Ezlc3tgtl"    [密钥查找]
  ├─ FUN_001a6bc8(data, len, key, keyLen, out)   [HMAC 签名]
  │   ├─ FUN_00164fc0(ctx, key, keyLen)          [HMAC_Init]
  │   ├─ FUN_001658a4(ctx)                       [ipad/opad 处理]
  │   ├─ FUN_00165ab8(ctx, data, dataLen)        [HMAC_Update]
  │   └─ FUN_00165b94(out, 0x20, ctx)            [HMAC_Final → 32 字节]
  ├─ NewByteArray(out_len)                        [JNI 0x580]
  └─ SetByteArrayRegion(result, output)           [JNI 0x680]

【返回 Java 层】
  → 32 字节 byte[]，被 ByteString.copyFrom() 包装为 protobuf sign 字段
```

---

## 十三、踩坑记录（补充 SO 层）

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| Java.perform hook st() 不触发 | ticket 已缓存（TTL ~3天），App 不请求新 ticket | 手动调用 `LibBili.st()` 触发 |
| `nr2a.a.value` 返回 null | Frida 字段/方法同名冲突，`_a` 也不行 | 用 Java 反射 `getDeclaredField` + `field.get(null)` |
| `Java.choose("nr2.a")` 找不到实例 | Kotlin object 单例的特殊内存布局 | 反射读取静态字段 |
| st() overload 签名猜错 | 以为第一个参数是 SortedMap，实际是 `byte[]` | 先枚举所有方法确认签名再 hook |
| 静态分析以为 key 是 "ec01" | FUN_001a6a80 被误判为 GetStringUTFChars | 动态 hook 验证返回值是 "Ezlc3tgtl" |
| 10 个偏移里找 st() | 逐个去 Ghidra 看太慢 | 手动调用 st() + 观察方法编号，一次定位 |

---

## 十四、SO 层逆向方法论总结

### 动静结合的完整工作流

```
1. Java 层准备（Frida 动态）
   ├─ 枚举方法签名 → 确认 st(byte[], Map, String)
   └─ 探查参数内容 → protobuf 设备信息

2. 定位 native 函数地址（Frida 动态）
   ├─ hook RegisterNatives → 捕获 11 个偏移
   └─ 手动调用 st() → 锁定 #10 (+0x9230)

3. 读懂函数逻辑（Ghidra 静态）
   ├─ 入口 FUN_00109230 → 透传壳
   ├─ 核心 FUN_001a5474 → JNI vtable 偏移还原
   ├─ HMAC FUN_001a6bc8 → 4 步标准流程
   └─ Init FUN_00164fc0 → 密钥预处理

4. 填充加密常量（Frida 动态）
   ├─ hook HMAC 函数 → 确认 key="Ezlc3tgtl"、output=32 字节
   └─ hook 密钥查找函数 → 确认 "ec01" → "Ezlc3tgtl" 映射

5. 验证结论
   └─ Native 版与 REST 版使用同一密钥 ✅
```

### 与 sign 逆向的对比

| 维度 | sign (LibBili.s) | ticket sign (LibBili.st) |
|------|------------------|-------------------------|
| 定位方式 | RegisterNatives + Ghidra 参数匹配 | RegisterNatives + **手动调用快速定位** |
| 入口偏移 | +0x9050 | +0x9230 |
| 算法 | MD5（流式 4×uint32 appSecret） | HMAC-SHA256 |
| 密钥 | `560c52ccd288fed045859ed18bffd973` | `Ezlc3tgtl` |
| 密钥存储 | 数据表 + 非连续偏移读取 | `FUN_001a6a80` 内部查表 |
| 静态可读性 | HMAC 函数清晰，外层 OLLVM 重 | 同上 |
| 动态验证 | hook sprintf 确认格式串 | hook HMAC 函数确认 key |

**核心经验**：
1. **静态搞结构，动态填数值** —— 两者缺一不可
2. **JNI vtable 偏移是 OLLVM 状态机中最可靠的锚点** —— 偏移值固定、语义明确、不受混淆影响
3. **手动触发比被动等待高效** —— 对于不常触发的函数，主动调用 + 观察是最快的定位方式
4. **datadiv_decode 加密的常量只能动态拿** —— 密钥、格式串等都不会以明文出现在 .so 中

---

## 十五、产出文件

| 文件 | 用途 |
|------|------|
| `bilibili_frida绕过/hook_st.js` | Java 层 hook LibBili.st()，捕获参数和返回值 |
| `bilibili_frida绕过/hook_st_native.js` | Native 层 hook HMAC 核心函数，验证密钥和输入输出 |
| `bilibili_frida绕过/hook_sign.js` | RegisterNatives 捕获（复用自 sign 逆向） |
| `bilibili_frida绕过/bypass.js` | Anti-Frida 绕过（复用自 sign 逆向） |

---

> 上一篇（Java 层）：本文第三~八章
> sign 逆向参考：[bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md)
> token 刷新研究：[bilibili_token刷新机制调研.md](./bilibili_token刷新机制调研.md)

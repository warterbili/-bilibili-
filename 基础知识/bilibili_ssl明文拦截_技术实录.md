# B站 App SSL 明文拦截全程实录

> **前置条件**：已完成 Frida 环境搭建，已用 `bypass.js` 绕过 `libmsaoaidsec.so` 检测。
> 参见：[frida_环境搭建与bilibili绕过.md](./frida_环境搭建与bilibili绕过.md)
>
> **目标设备**：小米 9（cepheus），PixelExperience 13.0，Frida 17.7.3，B站 v8.83.0
>
> **最终成果**：成功拦截 B站发评论的完整明文请求，包括评论内容、签名、access_key

---

## 一、目标与背景

绕过检测之后，下一步是**读取 B站的通信明文**：

- 看发评论时发出了什么数据（参数、签名逻辑）
- 理解 B站 gRPC 流量的结构
- 为后续分析 `sign` 签名算法做准备

流量全程 TLS 加密，tcpdump 只能抓密文（已在 [bilibili_grpc_抓包分析.md](./bilibili_grpc_抓包分析.md) 验证过）。要拿明文，有两条路：

| 方案 | 原理 | 难点 |
|------|------|------|
| **Java 层 Hook OkHttp** | Hook OkHttpClient.newCall，在 HTTP 序列化前读数据 | B站有 ART 方法表检测 |
| **Native SSL Hook** | Hook libssl.so 的 SSL_write/SSL_read，在加密前读明文 | 需要找到正确的 so 文件 |

---

## 二、REST 和 gRPC 是什么关系？我们是怎么发现评论走 REST 的？

### 先说结论：我们一开始判断错了

我们最初的假设是：**评论发送也走 gRPC**（因为评论接收走 gRPC）。

这个假设是错的。实际情况是：
- **评论接收**（别人发了评论推送给你）→ `grpc.biliapi.net`，走 **gRPC**
- **评论发送**（你发出一条评论）→ `api.bilibili.com`，走 **REST**

我们不是事先分析出来的，而是在调试过程中**被数据告知的**。

---

### 发现过程：从现象倒推

#### 第一个线索：gRPC 流量里看到了订阅，但没有看到发送

ssl_hook.js 开始工作后，能看到 `grpc.biliapi.net` 的流量：

```
→ grpc.biliapi.net [gRPC DATA stream=53 51B]
  f1(str/15)="service_comment"
  f2(str/13)="Android-2.9.4"
  f3(str/17)="116085684765239#1"   ← 视频ID，这是在订阅接收该视频的评论
```

这是 App 打开视频时**订阅评论推送**的请求（我要接收这个视频的新评论通知）。
之后能看到服务端持续推送数据（`←grpc.biliapi.net`）。

但是——我们发了评论之后，`grpc.biliapi.net` 上没有看到任何"发送评论"的请求。这说明**发送评论不走这条 gRPC 连接**。

#### 第二个线索：服务端返回了 JSON，不是 Protobuf

当我们加上 H2 非 gRPC DATA 帧的处理逻辑后，终端打印出了：

```
🔴 ← api.bilibili.com [H2 DATA stream=23 1503B→3236B]
  {"code":0,"message":"OK","data":{"rpid":290396424113,...}}
```

注意几点：
1. 主机是 `api.bilibili.com`，不是 `grpc.biliapi.net`
2. 内容是 **JSON**（`{"code":0,...}`），不是 Protobuf 二进制
3. 箭头是 `←`（收到），这是**服务端的响应**

这说明：请求发出去了，服务端返回了成功。请求的对端是 `api.bilibili.com`，格式是 JSON → 这是 **REST API**，不是 gRPC。

#### 第三个线索：找到了对应的请求 body

最终，补充了明文 body 的处理后，抓到了请求：

```
🔴 → api.bilibili.com [H2 DATA stream=27 900B]
  access_key=...&message=%E5%93%88%E5%93%88&oid=116063807212606&sign=...
```

这是 **URL 编码的键值对**（`key=value&key=value`），这是 REST 的典型格式，gRPC 绝对不会是这个样子。

---

### REST 是什么

REST（Representational State Transfer）是一种 Web API 的**设计风格**，不是协议。

最简单的理解：REST API 就是用 HTTP 请求来操作资源，URL 代表资源，HTTP 方法代表操作：

| HTTP 方法 | 含义 | 例子 |
|-----------|------|------|
| GET | 获取数据 | `GET /x/v2/reply/list?oid=123` 获取评论列表 |
| POST | 提交/创建数据 | `POST /x/v2/reply/add` 发表评论 |
| PUT | 更新数据 | `PUT /x/v2/reply/edit` 修改评论 |
| DELETE | 删除数据 | `DELETE /x/v2/reply/del` 删除评论 |

### POST 请求的结构

当 App 发评论时，发出的是一个 HTTP POST 请求。完整结构：

```
POST /x/v2/reply/add HTTP/1.1          ← 请求行（方法 + 路径 + 协议版本）
Host: api.bilibili.com                 ← 目标服务器
Content-Type: application/x-www-form-urlencoded  ← 数据格式
Content-Encoding: gzip                 ← 数据压缩方式
Content-Length: 455                    ← 数据字节长度
Authorization: Bearer xxx...           ← 身份认证
                                       ← 空行（分隔头部和正文）
oid=116063807212606&type=1&message=%E5%93%88%E5%93%88&sign=...  ← 请求正文
```

B站评论 POST 的正文是 **URL 编码的键值对**（`key=value&key2=value2`）：

```
access_key=9268870d...  ← 用户登录凭证（相当于 Cookie）
appkey=1d8b6e7d45233436 ← 应用标识符
message=%E5%93%88%E5%93%88  ← 评论内容（"哈哈" URL编码后）
oid=116063807212606     ← 视频 ID
type=1                  ← 内容类型（1=视频评论）
ts=1771442847           ← 当前时间戳（Unix 秒）
sign=83f5e24c3e2a...    ← 请求签名（防篡改）
```

### URL 编码是什么

`%E5%93%88%E5%93%88` 就是 "哈哈" 的 UTF-8 字节以十六进制表示：

```
"哈" = UTF-8: E5 93 88  → %E5%93%88
"哈" = UTF-8: E5 93 88  → %E5%93%88
```

URL 中不能直接出现中文和特殊字符，所以要编码。Python 解码：

```python
import urllib.parse
urllib.parse.unquote('%E5%93%88%E5%93%88')  # → '哈哈'
```

### gRPC vs REST 的区别

B站同时使用两种协议：

| 对比维度 | REST（HTTP/1.1）| gRPC（HTTP/2）|
|---------|---------------|--------------|
| 数据格式 | JSON 或 URL 编码文本 | Protobuf 二进制 |
| HTTP 版本 | HTTP/1.1 | HTTP/2 |
| 可读性 | 人类可直接阅读 | 需要解码才能读 |
| 传输效率 | 较低（文本体积大）| 较高（二进制紧凑）|
| 适用场景 | 普通接口 | 高频/实时/流式接口 |
| B站用途 | 评论提交、用户信息等 | 弹幕推送、实时评论流等 |

### 为什么同一个 App 两种协议都用？

把 B站发评论的完整链路画出来就清楚了：

```
你点击"发送"
    ↓
【写操作】POST /x/v2/reply/add → api.bilibili.com
    → 你"做"一件事（提交数据），是一次性请求
    → 用 REST：简单，请求完服务端返回结果就结束
    → 响应：{"code":0, "rpid":290396424113}（告诉你评论 ID）
    ↓
【读操作】订阅 service_comment → grpc.biliapi.net
    → 你"订阅"一个数据流（持续接收别人发的新评论）
    → 用 gRPC：连接建立一次，服务端持续推送，不需要每秒轮询
    → 响应：无限流（每当有人发评论就推一条过来）
```

一句话概括：
- **REST** 适合"请求-响应"模式（你问一次，我答一次，结束）
- **gRPC** 适合"流"模式（你订阅一次，我持续推送）

B站评论**发送**是一次性操作 → REST；评论**接收**是持续推送 → gRPC。这是有意的架构设计，不是混乱。

---

## 三、为什么 Charles 抓不到评论请求？

这是个非常关键的问题，而且答案能把整个架构串起来。

### Charles 的工作原理

Charles 是一个 **HTTP 代理（MITM Proxy）**，工作方式是这样的：

```
正常情况：
  App → 直接连接 → api.bilibili.com

配置了 Charles：
  App → Charles（中间人）→ api.bilibili.com
         ↑
    Charles 解密、显示内容、再重新加密转发
```

Charles 要能抓到流量，需要两个条件同时满足：
1. **App 的流量经过 Charles 的代理**（App 要听从系统代理设置）
2. **App 信任 Charles 的证书**（Charles 用自己的 CA 证书冒充服务器）

### B站为什么绕过了 Charles

B站的网络请求分两套：

```
第一套：OkHttp（Java 层）
    ↓ 使用系统 HttpURLConnection / ProxySelector
    ↓ 自动读取 Android 系统代理设置
    ↓ 使用系统 Conscrypt (libssl.so) 做 TLS
    → Charles 能拦截 ✓
    → 能抓到：首页推荐、搜索、视频信息等

第二套：libignet.so（C++ 原生层，B站自研网络库）
    ↓ 直接用 BSD socket 建立 TCP 连接
    ↓ 完全不读取 Android 系统代理设置
    ↓ 使用自带 BoringSSL (lib/arm64/libssl.so) 做 TLS
    → Charles 完全不知道这条连接存在 ✗
    → 抓不到：评论发送、gRPC 弹幕、P2P CDN 等
```

**Charles 的代理设置只对 Java 层（OkHttp）有效**。libignet.so 是原生 C++ 代码，它自己管理 socket，从来不问 Android 系统"代理地址是什么"，因此 Charles 连拦截的机会都没有。

### 为什么评论 POST 走 libignet.so，不走 OkHttp

这就是 B站架构的关键：

| 功能 | 使用的库 | Charles 可见？|
|------|---------|-------------|
| 首页、搜索、视频详情 | OkHttp | ✓ |
| 发表评论（POST /x/v2/reply/add）| **libignet.so** | ✗ |
| 实时弹幕/评论订阅（gRPC）| libignet.so | ✗ |
| P2P CDN（ali-edge.solseed.cn）| libignet.so | ✗ |

B站把所有"核心/敏感"接口都放进了 libignet.so 里，这样：
- 代理工具（Charles/mitmproxy）完全看不见
- 就算设置了系统代理也没用
- 普通的 SSL Pinning bypass（Hook Java 层证书验证）也无效

这也正是为什么我们需要 **Frida Hook libssl.so 的 SSL_write**——这是唯一能拿到 libignet.so 流量明文的地方。在加密之前、在 socket 发出之后，SSL_write 是必经之路。

### 一句话总结

> Charles 抓不到评论，不是因为评论走 gRPC，而是因为**发评论这件事走的是 libignet.so**，这个库直接建 TCP 连接，完全无视系统代理，Charles 根本插不进去。

---

## 四、B站评论接口详解

### 发表评论接口（REST POST）

我们实际抓到的完整请求：

```
→ api.bilibili.com  POST /x/v2/reply/add  HTTP/2（实际走 HTTP/2，但格式类似）
```

**完整参数（从 SSL 明文中提取）：**

```
access_key=9268870d42b7212148710905156f8721CjBAOXQg...（很长，是 OAuth token）
appkey=1d8b6e7d45233436
build=8830500                    ← App 版本号（8.83.0 的内部编号）
c_locale=zh-Hans_CN
channel=html5_search_google      ← 来源渠道
container_uuid=a535fbad-...      ← 界面容器 UUID
disable_rcmd=0
from_spmid=tm.recommend.0.0      ← 来源追踪（SPM = 商品位置模型）
goto=vertical_av
has_vote_option=false
message=%E5%93%88%E5%93%88       ← 评论内容 ★
mobi_app=android
oid=116063807212606               ← 目标视频/内容 ID ★
ordering=heat                    ← 评论排序方式
plat=2
platform=android
s_locale=zh-Hans_CN
scene=main
scm_action_id=50051A9E
spmid=main.ugc-video-detail-vertical.0.0
statistics={"appId":1,"platform":3,"version":"8.83.0","abtest":""}
sync_to_dynamic=false
track_id=all_0.router-pegasus-2479124-l46t4.1771442830538.472
ts=1771442847                    ← 时间戳（Unix 秒）★
type=1                           ← 内容类型（1=视频，12=专栏等）★
sign=83f5e24c3e2a92761f06d274ff412fb2  ← 请求签名 ★
```

**服务端响应（成功）：**

```json
{
  "code": 0,
  "message": "OK",
  "ttl": 1,
  "data": {
    "rpid": 290396424113,        ← 新评论的 ID
    "rpid_str": "290396424113",
    "dialog": 0,
    "root": 0,
    "parent": 0,
    "reply": {
      "rpid": 290396424113,
      "oid": 116063807212606,    ← 视频 ID
      "type": 1,
      "mid": 435163479,          ← 评论者 UID
      "ctime": 1771442847,       ← 发布时间戳
      "member": {
        "uname": "G......",      ← 用户名
        "avatar": "https://i0.hdslb.com/bfs/face/..."
      }
    }
  }
}
```

### sign 签名是什么

`sign=83f5e24c3e2a92761f06d274ff412fb2` 是 B站 API 的防篡改签名。

**原理（推测，基于公开分析）：**

1. 把所有参数按字母顺序排列
2. 拼接成 `key1=val1&key2=val2&...` 格式
3. 在末尾拼接 `appSecret`（硬编码在 App 里）
4. 对整个字符串计算 MD5

```python
import hashlib
params = sorted({"access_key":..., "appkey":..., "message":..., "ts":...}.items())
param_str = "&".join(f"{k}={v}" for k, v in params)
sign = hashlib.md5((param_str + APP_SECRET).encode()).hexdigest()
```

有了 sign，就可以在 Python 里构造合法请求，绕过 App 直接调用接口。这是逆向分析的最终目标之一。

### gRPC 评论订阅（service_comment）

评论**接收**走 gRPC，不走 REST。当你打开一个视频时，App 会向 `grpc.biliapi.net` 建立一条 gRPC 流，订阅实时评论推送：

```
→ grpc.biliapi.net  [gRPC DATA stream=53 51B]
  f1(str/15)="service_comment"
  f2(str/13)="Android-2.9.4"
  f3(str/17)="116085684765239#1"   ← 视频ID#类型
```

这是一个**服务器推送流**（Server Streaming RPC）：客户端发一次订阅请求，服务端持续推送新评论，不用客户端反复轮询。

---

## 四、第一条路：Java 层 Hook OkHttp（失败）

### 尝试

写了 `grpc_intercept.js`，核心是 Hook OkHttpClient 的发包入口：

```javascript
Java.perform(function () {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function (request) {
        var url = request.url().toString();
        var method = request.method();
        console.log("[REQ] " + method + " " + url);
        // 注意：不能读取 body！OkHttp RequestBody 是单次消费流，
        // body.writeTo(buf) 会消耗掉数据，导致实际请求 body 为空
        return this.newCall(request);
    };
});
```

运行：
```bash
frida -U -f tv.danmaku.bili -l bypass.js -l grpc_intercept.js
```

### 现象

注入成功，App 正常启动，但 **3 秒后** `Process terminated`。

### 原因：ART 方法表检测

`Java.perform` 在底层的操作：

```
Java.perform(callback)
    ↓
Frida 挂起 Java 线程
    ↓
修改 ART 运行时中目标方法的方法表指针（vtable）
    ↓
将指针指向我们的 JS 回调
```

B站的 `libmsaoaidsec.so` 除了检测 Frida 特征，还会**周期性扫描 ART 方法表**，发现方法指针被修改就退出。这个检测发生在我们 bypass.js 拦截之后，`bypass.js` 只阻止了线程创建，并没有阻止 ART 扫描。

> **关键结论一：在 B站上，只要用 `Java.perform` + 方法替换，就会在约 3 秒后被杀死。**

### 但还有第二个致命问题：即使绕过检测，Hook OkHttp 也没用

这一点我们当时没有立刻意识到，是后来整个调试完成之后才彻底想清楚的。

发评论的请求根本**不经过 OkHttp**：

```
OkHttp 负责的流量（可以被 hook 到）：
  首页推荐、视频信息、搜索、用户信息...

libignet.so 负责的流量（OkHttp 完全不知道）：
  ★ 发评论（POST /x/v2/reply/add）
  ★ gRPC 弹幕/评论推送
  ★ P2P CDN 视频流
```

B站把所有核心/敏感的网络请求都放进了自研的 C++ 库 `libignet.so` 里，OkHttp 只处理普通的非核心接口。

所以假设 ART 检测根本不存在、`Java.perform` 完全无副作用——我们 hook 了 OkHttpClient，终端里打出了所有 OkHttp 请求——也看不到任何发评论的流量，因为那条请求从头到尾就没经过 OkHttp。

**这意味着 Java 层 Hook 这条路有两个独立的死因：**

| 死因 | 能否绕过 |
|------|---------|
| ART 方法表检测 → 3 秒 crash | 理论上可以，但代价极高 |
| 评论根本不走 OkHttp | **无法绕过，是架构决定的** |

就算第一个问题解决了，第二个问题也会让你一无所获。Native SSL Hook 才是唯一正确路径。

---

## 五、"一定是 bypass.js 出了问题"——走弯路的心路历程

### 为什么会怀疑 bypass.js

crash 出现后，第一反应是：bypass.js 失效了？毕竟 bypass.js 是我们唯一的防护，一旦失效就会被杀。

看到的现象是一样的——`Process terminated`，于是陷入了"绕过没成功"的思维定势，花时间在各种新绕过策略上：

---

### 弯路一：bypass_v5.js —— "盲化策略"

**思路：** 既然 bypass.js 可能不够用，那就从另一个角度绕过——不阻止线程创建，而是**让线程正常跑，但让它什么都检测不到（盲化）**：

- Hook `strstr`：当搜索 "frida"、"gum-js-loop" 时返回 NULL（让 maps 扫描失效）
- Hook `connect`：当目标端口是 27042/27043 时返回失败（让端口扫描失效）
- Hook `open` + `read`：当读取 `/proc/self/maps` 时过滤掉 frida 相关行

```javascript
// Part 3: /proc/self/maps 过滤
Interceptor.attach(readAddr, {
    onLeave: function(retval) {
        if (!this.tracked) return;
        var len = retval.toInt32();
        // 读出内容，过滤含 frida 的行，写回去
        var str = buf.readUtf8String(len);
        var filtered = str.split('\n').filter(line =>
            line.indexOf('frida') === -1 && line.indexOf('gum-js') === -1
        ).join('\n');
        this.buf.writeUtf8String(filtered);
        retval.replace(ptr(filtered.length));
    }
});
```

**结果：** 直接 SIGSEGV（段错误），App 崩溃。

**原因：** `read` 这个系统调用非常底层，很多线程都会调用它读各种东西（不只是 maps）。`/proc/self/maps` 是内核提供的虚拟文件，读取时内核直接把数据放进 buf，这个 buf 有时指向内核管理的内存区域（如 `perfetto_hprof_` 线程读取 heap dump 时的 buf）。我们在 `onLeave` 里直接 `buf.writeUtf8String(...)` 覆写它，触发了写保护页的 SIGSEGV。

**教训：** Hook 越底层的函数，副作用越多。`read` 被整个进程所有线程共享调用，稍有不慎就崩溃。

---

### 弯路二：debug_pthread.js —— 确认 bypass.js 是否还在工作

怀疑 bypass.js 可能某种原因失效了，写了一个追踪脚本来验证：

```javascript
// 追踪所有 pthread_create 调用来源
var pthreadCreateAddr = findExport("libc.so", "pthread_create");
Interceptor.attach(pthreadCreateAddr, {
    onEnter: function (args) {
        var mod = Process.findModuleByAddress(this.returnAddress);
        console.log("[pthread_create] from=" + (mod ? mod.name : "unknown"));
    }
});
```

运行 `bypass.js + debug_pthread.js`，结果：App 正常运行，看到了来自其他库的 pthread_create，**但没有看到来自 libmsaoaidsec.so 的**——说明 bypass.js 完全正常，确实拦截了 msaoaidsec 的线程创建。

---

### 关键转折：用控制变量法确定问题根源

这才想到：既然 bypass.js 没问题，那是谁在 3 秒后杀死进程？

做了一个最小化测试：

```
测试一：bypass.js + debug_pthread.js（纯 Native，无 Java.perform）
→ 结果：App 稳定运行，不崩溃 ✓

测试二：bypass.js + grpc_intercept.js（含 Java.perform）
→ 结果：3 秒后崩溃 ✗

唯一差异：Java.perform 的存在
```

结论：**不是 bypass.js 的问题，是 `Java.perform` 本身触发了 B站第二层检测（ART 方法表扫描）。** bypass.js 从头到尾都是正确的。

---

### 心路历程总结

```
第一感受：bypass.js 肯定出问题了（错误归因）
    ↓
绕了一圈写了 bypass_v5.js（盲化策略）
    ↓
结果 bypass_v5.js 直接 SIGSEGV 崩溃
    ↓
更困惑：到底是哪里的问题？
    ↓
冷静下来，写 debug_pthread.js 单独验证 bypass.js
    ↓
确认：bypass.js 工作正常，msaoaidsec 线程被完全拦截
    ↓
控制变量：去掉 grpc_intercept.js → 不崩溃
加上 grpc_intercept.js → 3 秒崩溃
    ↓
根因确定：Java.perform = ART 方法表修改 = 被第二层检测秒杀
    ↓
策略转向：完全放弃 Java 层，转向 Native SSL Hook
```

> **逆向经验：遇到问题先用控制变量法缩小范围，不要一次改多个东西。每次只改一个变量，观察效果变化。**

---

## 六、如何找到正确的 so 文件——完整思考过程

这是整个调试过程中最需要"侦探思维"的环节。我们不是一步到位找到答案的，而是经历了"找到→失败→疑惑→重新推理→再找"的完整过程。

### 起点：Hook SSL_write 的思路从哪里来

决定放弃 Java 层 Hook 之后，问题变成了：**在哪个层面拦截流量？**

画出数据流：

```
App 业务逻辑（Java/C++）
    ↓ 明文
网络库（OkHttp / libignet.so）
    ↓ 明文
TLS 加密层（libssl.so）
    ↓  SSL_write(ssl*, buf, len)  ← 加密前的最后一道门
    ↓ 密文
TCP socket
    ↓ 密文
服务器
```

无论上层用什么协议（HTTP/1.1、HTTP/2、gRPC），数据要出去就必须经过 `SSL_write`。这个函数签名是标准 OpenSSL/BoringSSL C 接口，`buf` 参数就是加密前的明文，`len` 是长度。

**这就是为什么 hook SSL_write 能拦截所有 HTTPS 流量，而且跟 Java 层完全无关，不会触发 ART 检测。**

### 第一步：最自然的假设——只有一套 libssl.so

SSL_write 在 `libssl.so` 里，那就找 libssl.so。

Android 上有一个系统级的实现：`/apex/com.android.conscrypt/lib64/libssl.so`，这是 Google 维护的 BoringSSL，OkHttp 默认用它。

自然的第一反应：**hook 系统的 libssl.so，就能拿到所有流量。**

写了 find_ssl.js 来确认：

### 第二步：用 find_ssl.js 枚举 SSL 函数

```bash
frida -U -f tv.danmaku.bili -l bypass.js -l find_ssl.js
```

`find_ssl.js` 内容（诊断用，不需要长期保留）：

```javascript
// find_ssl.js - 枚举所有已加载模块，查找 SSL_write / SSL_read
var found = [];

Process.enumerateModules().forEach(function(mod) {
    try {
        mod.enumerateExports().forEach(function(e) {
            if (e.name === "SSL_write" || e.name === "SSL_read" ||
                e.name === "SSL_write_ex" || e.name === "SSL_read_ex") {
                found.push({ lib: mod.name, path: mod.path, name: e.name, addr: e.address });
            }
        });
    } catch(e) {}
});

if (found.length > 0) {
    console.log("[+] 找到 SSL 函数：");
    found.forEach(function(f) {
        console.log("  " + f.name + " @ " + f.addr + "  lib=" + f.lib);
        console.log("    path=" + f.path);
    });
} else {
    console.log("[-] 未找到，等待 10 秒后重试（可能还未加载）...");
    setTimeout(function() {
        Process.enumerateModules().forEach(function(mod) {
            try {
                mod.enumerateExports().forEach(function(e) {
                    if (e.name === "SSL_write" || e.name === "SSL_read") {
                        console.log("[+] (延迟) " + e.name + " in " + mod.name + " @ " + e.address);
                    }
                });
            } catch(e) {}
        });
    }, 10000);
}

// 同时列出所有含 ssl/crypto/conscrypt/boring 的模块
console.log("[*] 含 ssl/crypto/conscrypt/boring 的模块：");
Process.enumerateModules().forEach(function(mod) {
    var low = mod.name.toLowerCase();
    if (low.indexOf("ssl") !== -1 || low.indexOf("crypto") !== -1 ||
        low.indexOf("conscrypt") !== -1 || low.indexOf("boring") !== -1) {
        console.log("  " + mod.name + "  " + mod.path);
    }
});
```

### 第三步：第一次尝试——只 hook 系统 Conscrypt，发现缺失流量

find_ssl.js 的输出：

```
[+] 找到 SSL 函数：
  SSL_write @ 0x75aa2828fc  lib=libssl.so
    path=/apex/com.android.conscrypt/lib64/libssl.so   ← 系统 Conscrypt

[*] 含 ssl/crypto/conscrypt/boring 的模块：
  libssl.so        /apex/com.android.conscrypt/lib64/libssl.so
  libcrypto.so     /apex/com.android.conscrypt/lib64/libcrypto.so
  libjavacrypto.so /apex/com.android.conscrypt/lib64/libjavacrypto.so
```

只找到一个 libssl.so，路径在系统目录。Hook 上去，发评论——**什么都没有**。

这里出现了第一个疑问：**Hook 成功了，为什么看不到评论流量？**

有两种可能：
1. 评论流量走的是这个 libssl.so，但被我们的过滤逻辑漏掉了
2. 评论流量根本没有经过这个 libssl.so，走的是别的地方

### 第四步：关键推理——B站有没有自己的 libssl.so？

B站是国内顶级 App，对安全和性能都有很高要求。想到一个问题：

**像 gRPC 这种复杂协议，B站会直接用系统的网络栈，还是自己打包一套？**

回想起之前 Charles 抓包的经验：Charles 能抓到首页和搜索，但抓不到 gRPC 流量——即使在同一台手机上。如果都走系统 Conscrypt，Charles 应该能抓到所有的，但它抓不到 gRPC。这说明 gRPC 流量走的是**另一套 TLS 实现**，绕过了系统代理。

**这就意味着 B站很可能内置了自己的 BoringSSL。**

### 第五步：在 App 运行起来之后，手动枚举所有模块

等 App 完全启动、建立过 gRPC 连接之后，在 Frida REPL 里把所有加载的模块打出来：

```javascript
Process.enumerateModules().forEach(function(m) {
    console.log(m.size + "  " + m.name + "  " + m.path);
})
```

在输出里立刻发现了两个可疑文件：

```
396K    libssl.so    /data/app/~~xxx/tv.danmaku.bili-xxx/lib/arm64/libssl.so  ← ！
5400K   libignet.so  /data/app/~~xxx/tv.danmaku.bili-xxx/lib/arm64/libignet.so ← ！！
```

**两个关键发现：**

1. **又一个 libssl.so**，但路径在 B站自己的 app 目录下（`/data/app/.../tv.danmaku.bili-xxx/lib/arm64/`），不是系统目录
2. **libignet.so，5.4MB**——这个体积意味着什么？一个正常的网络辅助库几十到几百 KB 就够了，5.4MB 说明里面打包了大量代码。直觉告诉我这就是 B站的"网络全家桶"

### 第六步：验证 libignet.so 的身份——直接在 Frida REPL 里查

不需要拉文件、不需要外部工具，直接在 Frida 控制台里查 libignet.so 导出了哪些符号：

```javascript
// Frida REPL 中输入：
var ignet = Process.findModuleByName("libignet.so");
ignet.enumerateExports().forEach(function(e) {
    // 找含 grpc / ssl / proto 关键词的导出符号
    var low = e.name.toLowerCase();
    if (low.indexOf("grpc") !== -1 || low.indexOf("ssl") !== -1 ||
        low.indexOf("proto") !== -1) {
        console.log(e.name);
    }
});
```

输出里能看到大量 `grpc_*`、`SSL_*`、`protobuf_*` 开头的符号，以及 B站自己的符号如 `bilibili_` 前缀的函数名。

还可以直接查它依赖了哪个 libssl.so：

```javascript
// 看 libignet.so 加载时间前后，libssl.so 出现在哪个路径下
Process.enumerateModules().forEach(function(m) {
    if (m.name === "libssl.so") {
        console.log(m.path + "  size=" + m.size);
    }
});
// 输出：
// /apex/com.android.conscrypt/lib64/libssl.so  size=...   ← 系统的
// /data/app/~~xxx/tv.danmaku.bili-xxx/lib/arm64/libssl.so  size=396K  ← B站的
```

B站的 libssl.so 路径和 libignet.so 在同一目录（`lib/arm64/`），这就是配套关系的直接证据。

**结论彻底确认：libignet.so 是 B站的内部网络库，内含 gRPC-core + Protobuf + BoringSSL 全套**。它加载了旁边的 libssl.so（B站自带版本），跟系统 Conscrypt 完全独立。

### 第七步：为什么第一次 find_ssl.js 没找到它？

这是最后一个谜：刚才 find_ssl.js 运行时明明枚举了所有模块，为什么没有发现 B站的 libssl.so？

答案是：**延迟加载（Lazy Loading）**。

```
App 启动
    ↓
libignet.so 被加载（但它的 libssl.so 还没加载）
    ↓
find_ssl.js 此时运行 → 只能看到系统 Conscrypt
    ↓
用户打开视频页面 / 建立 gRPC 连接
    ↓
libignet.so 第一次需要建立 TLS 连接
    ↓
此时 libignet.so 才 dlopen 加载旁边的 libssl.so
    ↓
REPL 手动枚举 → 现在能看到了
```

B站的 libssl.so 不在启动时加载，而是在**第一次发起网络请求时**才动态加载。所以脚本注入的时候它还不存在，枚举不到。

这就是为什么最终方案需要**轮询机制**：用 `setInterval` 每隔 500ms 检查一次有没有新的 libssl.so 出现，出现了就立刻 hook 上去。

### 确认 B站 libssl.so 有 SSL_write

```javascript
var mod = Process.findModuleByPath(
    "/data/app/~~xxx/tv.danmaku.bili-xxx/lib/arm64/libssl.so"
);
mod.enumerateExports().forEach(function(e) {
    if (e.name === "SSL_write") console.log(e.name + " @ " + e.address);
})
// 输出：SSL_write @ 0x74ea596504
```

### 第五步：理解为什么有两套 libssl.so

**B站的网络架构：**

```
App Java 层
    ├── OkHttp（通用 REST API）
    │     └── 系统 Conscrypt TLS（系统 libssl.so）
    │           → api.bilibili.com（发评论、获取视频信息等）
    │
    └── libignet.so（B站内部网络库，5.4MB）
          ├── 内嵌 gRPC-core
          ├── 内嵌 Protobuf
          └── 内嵌 BoringSSL（B站自带 libssl.so）
                → grpc.biliapi.net（实时评论/弹幕推送）
                → broadcast.chat.bilibili.com（聊天）
                → ali-edge.solseed.cn（CDN/P2P）
```

**为什么 B站要内嵌自己的 BoringSSL，而不用系统的 Conscrypt？**

1. **版本控制**：系统 TLS 库随 Android 版本更新，可能引入不兼容；自带版本完全可控
2. **证书绑定（Certificate Pinning）**：可以在 BoringSSL 层面做更底层的证书校验，比 Java 层更难绕过
3. **定制化**：可以修改 BoringSSL 源码，添加私有功能（比如自定义加密算法、流量混淆）

### 第六步：找 libignet.so 的线索（如何知道是这个文件）

有三种方法：

**方法一：看文件大小**

一个 5.4MB 的 `libignet.so` 里面包含了 gRPC-core（约 3MB）+ Protobuf（约 1MB）+ BoringSSL（约 1.5MB）。这个体积特征非常明显，一眼能认出来是"网络库全家桶"。

**方法二：搜索 gRPC 特征字符串**

把 B站 APK 解压，对 libignet.so 做字符串搜索：

```bash
strings libignet.so | grep -i "grpc\|biliapi\|service_comment"
```

能找到：`grpc.biliapi.net`、`service_comment`、`bilibili.community`等 gRPC 服务端点名称。

**方法三：查 ELF 导入表（依赖关系）**

```bash
readelf -d libignet.so | grep NEEDED
```

会看到 `libssl.so`（B站自带的那个）作为依赖项。这说明 libignet.so 和它是配套的。

---

## 七、一个重要的反思：我们差点因为"假设"而失败

### 我们一直在找 gRPC，但评论根本不是 gRPC

回顾整个过程：

- 我们从 tcpdump 抓包里看到 `grpc.biliapi.net`
- 用 Wireshark 过滤到 `tls.handshake.extensions_server_name == "grpc.biliapi.net"`
- 于是在脑子里建立了一个假设：**评论 = gRPC**
- 所以写了 `grpc_intercept.js`，Hook OkHttp 的 gRPC 入口
- 所以在 ssl_hook.js 里重点关注 `grpc.biliapi.net` 的流量
- 所以看到 `service_comment` 订阅就觉得"快找到了"

但实际上，**评论发送走的是 REST**，跟 gRPC 没有关系。`service_comment` 是接收推送用的，不是发送用的。我们绕了很大一圈，最后是被数据纠正的，不是被我们的推理引导到的。

### 如果 B站把评论发送也放进 gRPC，我们才能更快找到

这里有一个反直觉的地方：

**我们一直在找 gRPC，反而是因为评论不是 gRPC 才让我们困惑了很久。** 如果评论发送也在 `grpc.biliapi.net`，我们在 ssl_hook.js 里看到 service_comment 之后很快就能解析出内容了。

正是"评论在 grpc 域名下的 gRPC 订阅流里 + 评论发送却去了 api.bilibili.com 的 REST 接口"这个分裂的架构，让我们的假设一直是错的。

### 为什么最后还是成功了？

因为我们的核心工具 `SSL_write hook` **从一开始就是协议无关的**。

```
我们的假设（错的）：
  评论 → gRPC → grpc.biliapi.net

现实（对的）：
  评论发送 → REST → api.bilibili.com
  评论接收 → gRPC → grpc.biliapi.net

但 SSL_write hook 不在乎这个区别：
  无论 REST 还是 gRPC，无论去哪个域名，
  数据加密前都必须经过 SSL_write，
  我们都能拿到。
```

SSL_write 处在协议栈的最底层，它不知道也不关心上面跑的是什么协议。这个 hook 点天然地覆盖了所有可能性，替我们兜住了错误的假设。

### 给读者的启发

**1. 先捞数据，后做分类**

不要先假设协议，再去找对应的 hook 点。正确顺序是：

```
❌ 错误顺序：
  假设"评论是 gRPC" → 找 gRPC hook 点 → 抓不到 → 困惑

✅ 正确顺序：
  Hook SSL_write（捞所有数据）→ 触发目标操作 → 看哪条流量出现了 → 再分析它是什么协议
```

**2. Hook 层次越低，假设越少，覆盖越全**

| Hook 层次 | 能捕获什么 | 前提假设 |
|-----------|-----------|---------|
| Java OkHttp | OkHttp 发出的 HTTP 请求 | 必须走 OkHttp，必须是 Java |
| gRPC 框架层 | gRPC 调用 | 必须是 gRPC 协议 |
| SSL_write | **所有 TLS 流量** | 只需要用 TLS，协议任意 |
| TCP socket | 所有 TCP 流量（含密文）| 无假设，但看不到明文 |

越往下 hook，前提假设越少，漏网之鱼越少。SSL_write 是明文可读的最低层，是逆向网络流量的黄金 hook 点。

**3. 让数据告诉你答案，不要让假设引导你**

最终找到评论的方式不是"我们推理出来评论在 api.bilibili.com 用 REST"，而是：

```
我们把所有 SSL 流量都捞上来
    ↓
发了一条评论
    ↓
有一条新的 api.bilibili.com 响应出现了，内容是 {"code":0, "rpid":...}
    ↓
数据告诉我们：评论在这里，它是 REST
```

不是我们找到了评论，是评论找到了我们。这是逆向分析的正确姿势。

---

## 八、Native SSL Hook 的完整实现

### 数据流向（理解为什么要 hook SSL_write）

```
评论文字 "哈哈"
    ↓
App 序列化 → URL 编码 → "message=%E5%93%88%E5%93%88&oid=..."
    ↓
HTTP/2 分帧
    ↓
libssl.so::SSL_write(ssl*, buf="message=...", len=900)  ← 在这里截获
    ↓
BoringSSL 使用 TLS 密钥加密
    ↓
网卡发出密文
    ↓
api.bilibili.com 服务器
```

### ssl_hook.js 完整代码

```javascript
// ssl_hook.js v3 - 专注捕获评论/有效流量，过滤噪音
// 配合 bypass.js 使用，无 Java.perform

var sslHostMap = {};

// ── gzip 解压（使用系统 libz.so）────────────────────────────
var _inflateInit2 = null, _inflate = null, _inflateEnd = null;
(function() {
    var libz = Process.findModuleByName("libz.so");
    if (!libz) return;
    libz.enumerateExports().forEach(function(e) {
        if (e.name === "inflateInit2_") _inflateInit2 = new NativeFunction(e.address, 'int', ['pointer','int','pointer','int']);
        if (e.name === "inflate")       _inflate     = new NativeFunction(e.address, 'int', ['pointer','int']);
        if (e.name === "inflateEnd")    _inflateEnd  = new NativeFunction(e.address, 'int', ['pointer']);
    });
    if (_inflateInit2) console.log("[+] zlib gzip decompression ready");
})();

function decompressGzip(srcBytes, offset, len) {
    if (!_inflateInit2 || !_inflate || !_inflateEnd) return null;
    try {
        // z_stream on ARM64: next_in@0, avail_in@8, total_in@16,
        //                    next_out@24, avail_out@32, total_out@40
        var zs = Memory.alloc(128); zs.writeByteArray(new Array(128).fill(0));
        var src = Memory.alloc(len);
        for (var i = 0; i < len; i++) src.add(i).writeU8(srcBytes[offset + i]);
        var dstSize = Math.min(len * 20, 65536);
        var dst = Memory.alloc(dstSize);
        zs.writePointer(src);               // next_in
        zs.add(8).writeU32(len);            // avail_in
        zs.add(24).writePointer(dst);       // next_out
        zs.add(32).writeU32(dstSize);       // avail_out
        // wbits=47 = 15+32: gzip decode mode
        var ver = Memory.allocUtf8String("1.2.11");
        if (_inflateInit2(zs, 47, ver, 112) !== 0) return null;  // 112 = sizeof(z_stream) on ARM64
        var ret = _inflate(zs, 4); // Z_FINISH=4
        _inflateEnd(zs);
        var totalOut = zs.add(40).readU32();
        if (totalOut > 0) return new Uint8Array(dst.readByteArray(totalOut));
    } catch(e) {}
    return null;
}

// ── Protobuf 解析 ─────────────────────────────────────────────
function decodeProto(bytes, offset, limit) {
    var result = [], pos = offset;
    try {
        while (pos < limit && result.length < 20) {
            var b = bytes[pos++] & 0xff;
            var field = b >>> 3, wire = b & 7;
            if (wire === 0) {
                var v = 0, sh = 0, bv;
                do { bv = bytes[pos++] & 0xff; v |= (bv & 0x7f) << sh; sh += 7; } while (bv & 0x80);
                result.push("  f" + field + "(int)=" + v);
            } else if (wire === 2) {
                var l = 0, sh = 0, bv;
                do { bv = bytes[pos++] & 0xff; l |= (bv & 0x7f) << sh; sh += 7; } while (bv & 0x80);
                var s = "";
                for (var i = 0; i < Math.min(l, 120); i++) {
                    var c = bytes[pos + i] & 0xff;
                    s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                }
                result.push("  f" + field + "(str/" + l + ")=\"" + s + "\"");
                pos += l;
            } else if (wire === 5) { pos += 4; }
              else if (wire === 1) { pos += 8; }
              else break;
        }
    } catch(e) {}
    return result.join("\n");
}

// ── HTTP/2 帧解析，返回是否有内容 ────────────────────────────
function parseAndLog(bytes, total, prefix) {
    var pos = 0, printed = false;
    // 检测 HTTP/1.1 文本协议（POST/GET/HTTP 开头）
    if (total > 4) {
        var s4 = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
        if (s4 === "POST" || s4 === "GET " || s4 === "HTTP") {
            var hdr = "";
            for (var i = 0; i < Math.min(total, 2048); i++) {
                var c = bytes[i];
                hdr += (c >= 32 && c < 127 || c === 10 || c === 13) ? String.fromCharCode(c) : ".";
            }
            var isReply = hdr.indexOf("/reply") !== -1 || hdr.indexOf("message=") !== -1;
            if (!isReply) return false;

            console.log("\n🔴 " + prefix + " [HTTP] " + total + "B");
            console.log("  " + hdr.substring(0, 300).replace(/\r\n/g, " | "));

            // 找 body 起始（\r\n\r\n 之后）
            var bodyStart = -1;
            for (var i = 0; i < total - 3; i++) {
                if (bytes[i]===13 && bytes[i+1]===10 && bytes[i+2]===13 && bytes[i+3]===10) {
                    bodyStart = i + 4; break;
                }
            }
            if (bodyStart !== -1 && bodyStart < total) {
                var bodyLen = total - bodyStart;
                if (bytes[bodyStart] === 0x1f && bytes[bodyStart+1] === 0x8b) {
                    var dec = decompressGzip(bytes, bodyStart, bodyLen);
                    if (dec) {
                        var ds = "";
                        for (var i = 0; i < Math.min(dec.length, 800); i++) {
                            var c = dec[i]; ds += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                        }
                        console.log("  ★ body(解压): " + ds);
                    } else {
                        console.log("  body gzip 解压失败, len=" + bodyLen);
                    }
                } else {
                    var bs = "";
                    for (var i = 0; i < Math.min(bodyLen, 800); i++) {
                        var c = bytes[bodyStart+i]; bs += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                    }
                    console.log("  ★ body: " + bs);
                }
            }
            return true;
        }
    }
    // 跳过 HTTP/2 连接序言
    if (total >= 24) {
        var pre = "";
        for (var i = 0; i < 24; i++) pre += String.fromCharCode(bytes[i]);
        if (pre === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") pos = 24;
    }
    while (pos + 9 <= total) {
        var flen  = (bytes[pos] << 16) | (bytes[pos+1] << 8) | bytes[pos+2];
        var ftype = bytes[pos+3];
        var fflg  = bytes[pos+4];
        var fsid  = ((bytes[pos+5] & 0x7f) << 24) | (bytes[pos+6] << 16) | (bytes[pos+7] << 8) | bytes[pos+8];
        pos += 9;
        if (flen > total - pos || flen > 65536) break;
        // 只处理 DATA 帧（type=0），跳过 SETTINGS/PING/HEADERS（无法解 HPACK）
        if (ftype === 0x00 && flen >= 5) {
            var gc = bytes[pos];
            var gl = (bytes[pos+1]<<24)|(bytes[pos+2]<<16)|(bytes[pos+3]<<8)|bytes[pos+4];
            if (gc === 0 && gl > 0 && gl <= flen - 5) {
                // 非压缩 gRPC，直接解析 Protobuf
                var pb = decodeProto(bytes, pos + 5, pos + 5 + gl);
                if (pb) {
                    if (!printed) {
                        console.log("\n" + prefix + " [gRPC DATA stream=" + fsid + " " + gl + "B]");
                        printed = true;
                    }
                    console.log(pb);
                }
            } else if (gc === 1 && gl > 0 && gl <= flen - 5) {
                // 压缩 gRPC：先 gzip 解压，再解析 Protobuf
                var dec = decompressGzip(bytes, pos + 5, gl);
                if (dec) {
                    var pb = decodeProto(dec, 0, dec.length);
                    if (!printed) {
                        console.log("\n" + prefix + " [gRPC DATA(gz) stream=" + fsid + " " + gl + "B→" + dec.length + "B]");
                        printed = true;
                    }
                    if (pb) console.log(pb);
                } else {
                    var hex = "";
                    for (var hi = 0; hi < Math.min(gl, 32); hi++) {
                        var hb = bytes[pos + 5 + hi].toString(16);
                        hex += (hb.length < 2 ? "0" : "") + hb + " ";
                    }
                    console.log("\n" + prefix + " [gRPC DATA(gz) stream=" + fsid + " decompress FAIL] hex=" + hex);
                }
            } else if (flen > 4) {
                // 非 gRPC 的 H2 DATA 帧（普通 REST 请求体，gc 不是 0/1）
                var bodyBytes = bytes, bodyOff = pos, bodyLen2 = flen;
                var decoded2 = null;
                if (bytes[pos] === 0x1f && bytes[pos+1] === 0x8b) {
                    decoded2 = decompressGzip(bytes, pos, flen);
                    if (decoded2) { bodyBytes = decoded2; bodyOff = 0; bodyLen2 = decoded2.length; }
                }
                var ds2 = "", rdbl = 0;
                for (var di = 0; di < Math.min(bodyLen2, 1200); di++) {
                    var dc = bodyBytes[bodyOff + di];
                    if ((dc >= 32 && dc < 127) || dc === 10 || dc === 13) { ds2 += String.fromCharCode(dc); rdbl++; }
                    else ds2 += ".";
                }
                var hasKw = ds2.indexOf("message") !== -1 || ds2.indexOf("reply") !== -1 ||
                            ds2.indexOf("comment") !== -1 || ds2.indexOf("oid") !== -1;
                if (hasKw || rdbl / Math.min(bodyLen2, 200) > 0.5) {
                    if (!printed) {
                        var tag = decoded2 ? flen + "B→" + bodyLen2 + "B" : flen + "B";
                        console.log("\n🔴 " + prefix + " [H2 DATA stream=" + fsid + " " + tag + "]");
                        printed = true;
                    }
                    console.log("  " + ds2.substring(0, 1000));
                }
            }
        }
        pos += flen;
    }
    return printed;
}

// ── 统计可读字节比例 ──────────────────────────────────────────
function readableRatio(bytes, len) {
    var readable = 0, check = Math.min(len, 200);
    for (var i = 0; i < check; i++) {
        var c = bytes[i];
        if ((c >= 32 && c < 127) || c === 10 || c === 13) readable++;
    }
    return readable / check;
}

// ── 主日志函数 ────────────────────────────────────────────────
function logTraffic(dir, host, bufPtr, len) {
    if (len <= 20) return;   // 跳过心跳/PING 小包
    if (len <= 30) return;   // 跳过纯 SETTINGS 帧

    var label = dir + (host || "?");
    try {
        var bytes = new Uint8Array(bufPtr.readByteArray(len));
        var ratio = readableRatio(bytes, len);
        var showed = parseAndLog(bytes, len, label);

        // 未被 parseAndLog 处理，但可读性高，含关键词也显示
        if (!showed && ratio > 0.6 && len > 50) {
            var s = "";
            for (var i = 0; i < Math.min(len, 1000); i++) {
                var c = bytes[i]; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
            }
            if (s.indexOf("message") !== -1 || s.indexOf("reply") !== -1 ||
                s.indexOf("comment") !== -1 || s.indexOf("code") !== -1 ||
                s.indexOf("bilibili") !== -1 || s.indexOf("grpc") !== -1) {
                console.log("\n" + label + " [TEXT " + len + "B]");
                console.log("  " + s.substring(0, 500));
            }
        }
    } catch(e) {}
}

// ── 钩住一个 libssl.so 实例 ───────────────────────────────────
function hookSslLib(mod) {
    var writeAddr = null, readAddr = null, setHostAddr = null, getSnAddr = null;
    try {
        mod.enumerateExports().forEach(function(e) {
            if (e.name === "SSL_write")                writeAddr   = e.address;
            if (e.name === "SSL_read")                 readAddr    = e.address;
            if (e.name === "SSL_set_tlsext_host_name") setHostAddr = e.address;
            if (e.name === "SSL_get_servername")       getSnAddr   = e.address;
        });
    } catch(e) { return; }

    var getSn = getSnAddr ? new NativeFunction(getSnAddr, 'pointer', ['pointer', 'int']) : null;
    function getHost(ssl) {
        var k = ssl.toString();
        if (sslHostMap[k]) return sslHostMap[k];
        if (!getSn) return "";
        try { var p = getSn(ssl, 0); return p.isNull() ? "" : p.readCString(); } catch(e) { return ""; }
    }

    if (setHostAddr) {
        Interceptor.attach(setHostAddr, {
            onEnter: function(args) {
                try { sslHostMap[args[0].toString()] = args[1].readCString(); } catch(e) {}
            }
        });
    }
    if (writeAddr) {
        Interceptor.attach(writeAddr, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len <= 0 || len > 131072) return;
                logTraffic("→", getHost(args[0]), args[1], len);
            }
        });
        console.log("[+] SSL_write in " + mod.name + " (" + mod.path.split("/").slice(-3,-1).join("/") + ")");
    }
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function(args) { this.ssl = args[0]; this.buf = args[1]; },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len <= 0) return;
                logTraffic("←", getHost(this.ssl), this.buf, len);
            }
        });
        console.log("[+] SSL_read  in " + mod.name + " (" + mod.path.split("/").slice(-3,-1).join("/") + ")");
    }
}

// ── 轮询加载所有 libssl.so（含延迟加载的 B站版本）────────────
var hookedPaths = {};
function tryHookAll() {
    Process.enumerateModules().forEach(function(mod) {
        if (mod.name === "libssl.so" && !hookedPaths[mod.path]) {
            hookedPaths[mod.path] = true;
            hookSslLib(mod);
        }
    });
}
tryHookAll();
var checkCount = 0;
var poller = setInterval(function() {
    tryHookAll();
    if (++checkCount >= 20) clearInterval(poller);
}, 500);

console.log("[*] ssl_hook.js v3 ready — 只显示评论/有效内容，过滤心跳噪音");
```

---

## 八、bypass.js 完整代码

```javascript
// 绕过 B站 libmsaoaidsec.so 反 Frida 检测
// 关键修复：用 enumerateExports() 找 dlsym 真实地址
//           Module.findExportByName() 返回的是 PLT stub 无法 hook

var fakeFunc = new NativeCallback(function() {
    console.log("[+] fake pthread_create called, suppressed");
    return 0;
}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
console.log("[*] Fake function @ " + fakeFunc);

function findDlsymReal() {
    var libdl = Process.findModuleByName("libdl.so");
    if (!libdl) { console.log("[-] libdl.so not found"); return null; }
    var addr = null;
    libdl.enumerateExports().forEach(function(exp) {
        if (exp.name === "dlsym") addr = exp.address;
    });
    return addr;
}

var dlsymAddr = findDlsymReal();
if (!dlsymAddr) {
    console.log("[-] dlsym not found, abort");
} else {
    console.log("[+] dlsym real address: " + dlsymAddr);
    try {
        Interceptor.attach(dlsymAddr, {
            onEnter: function(args) {
                try {
                    this.symbol = args[1].isNull() ? "" : args[1].readCString();
                } catch(e) { this.symbol = ""; }
            },
            onLeave: function(retval) {
                if (this.symbol === "pthread_create" || this.symbol === "pthread_join") {
                    try {
                        var mod = Process.findModuleByAddress(this.returnAddress);
                        if (mod && mod.name.indexOf("msaoaidsec") !== -1) {
                            console.log("[+] Blocked dlsym(\"" + this.symbol + "\") from " + mod.name);
                            retval.replace(fakeFunc);
                        }
                    } catch(e) { console.log("[-] handler error: " + e); }
                }
            }
        });
        console.log("[+] dlsym hooked successfully");
    } catch(e) {
        console.log("[-] Failed to hook dlsym: " + e);
    }
}

console.log("[*] bypass ready");
```

---

## 九、gzip 解压的 z_stream 大小 Bug 详解

### 问题现象

数据有正确的 gzip magic bytes（`1f 8b 08`），但解压始终失败：

```
←grpc.biliapi.net [gRPC DATA(gz) stream=53 decompress FAIL] hex=1f 8b 08 00 ...
```

### 排查过程

1. `1f 8b` 是 gzip magic，格式正确 → 数据本身没问题
2. windowBits = 47（= 15+32，gzip 模式）正确
3. 版本字符串 "1.2.11" 正确
4. 唯一剩下的参数：`stream_size`，我们传了 128（内存 buffer 的大小）

### 根本原因

`inflateInit2_` 的第四个参数是 `sizeof(z_stream)`，这是 zlib 的 **ABI 兼容性校验**机制：

```c
// zlib 源码 inflate.c：
int ZEXPORT inflateInit2_(z_streamp strm, int windowBits,
                          const char *version, int stream_size) {
    // 版本检查
    if (version == Z_NULL || version[0] != ZLIB_VERSION[0])
        return Z_VERSION_ERROR;
    // 结构体大小检查 ← 这里！
    if (stream_size != (int)(sizeof(z_stream)))
        return Z_VERSION_ERROR;
    // ...
}
```

`sizeof(z_stream)` 在 ARM64 Android 上是 **112 字节**，我们传了 128，校验失败，直接返回 `Z_VERSION_ERROR`（-6）。

我们检查 `!== 0` 就认为失败，然后 `return null`，导致所有 gzip 数据都解压失败。

### 修复

```javascript
// 错误：
if (_inflateInit2(zs, 47, ver, 128) !== 0) return null;

// 正确：
if (_inflateInit2(zs, 47, ver, 112) !== 0) return null;
```

---

## 十、三种 H2 DATA 帧的区别

同样是 HTTP/2 DATA 帧，内容格式完全不同：

### 情况一：gRPC（未压缩）

```
┌────┬───────────┬──────────────────────────┐
│ 00 │ 00 00 0F 2B│ [Protobuf 字段...]       │
└────┴───────────┴──────────────────────────┘
  ↑       ↑
  gc=0   gl=3883（消息长度）
```

`gc=0` 且 `gl` 符合范围 → 直接解析 Protobuf

### 情况二：gRPC（gzip 压缩）

```
┌────┬───────────┬──────────────────────────┐
│ 01 │ 00 00 03 A5│ 1f 8b 08 ... [压缩数据] │
└────┴───────────┴──────────────────────────┘
  ↑       ↑
  gc=1   gl=933（压缩后长度）
```

`gc=1` → 先 gzip 解压，再解析 Protobuf

### 情况三：普通 REST 请求 body（非 gRPC）

```
┌──────────────────────────────────────────────┐
│ 1f 8b 08 00 00 ... [gzip 压缩的表单数据]      │
└──────────────────────────────────────────────┘
  ↑
  不是 gc，这就是 body 的第一个字节 = 0x1f（gzip magic）
```

`bytes[0]=0x1f`，不是 0 或 1 → 不是 gRPC 格式。需要直接把整个 DATA 帧 payload 当 gzip 解压。

**关键：如何区分 gRPC 和普通 REST？**

- gRPC：`gc = 0 or 1`，且后面的 `gl`（4字节大端长度）在合理范围内
- REST：第一个字节不是 0/1，或者 gl 值超出 payload 范围

发评论走的是情况三，这就是为什么早期版本的脚本完全看不到评论内容。

---

## 十一、完整流量链路

发一条评论，背后的完整网络交互：

```
1. 用户点"发送"
      ↓
2. → api.bilibili.com  POST /x/v2/reply/add
      Content-Encoding: gzip
      Body(解压后): access_key=...&message=%E5%93%88%E5%93%88&oid=116063807212606&sign=...
      ↓
3. ← api.bilibili.com  {"code":0,"data":{"rpid":290396424113,...}}
      ↓
4. → dataflow.biliapi.com  埋点上报（analytics，记录用户行为）
      eventId: community.public-community.text-field.send.click
      ↓
5. ← grpc.biliapi.net  service_comment 推送（其他用户的评论/弹幕推送回来）
```

步骤 2-3 是发评论的核心，步骤 4 是埋点，步骤 5 是订阅接收。

---

## 十二、运行指令

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" -l "C:/lsd_project/app_reverse/bilibili_frida绕过/ssl_hook.js"
```

预期启动输出：
```
[*] Fake function @ 0x7...
[+] dlsym real address: 0x786ce8d044
[+] dlsym hooked successfully
[*] bypass ready
[+] zlib gzip decompression ready
[+] SSL_write in libssl.so (com.android.conscrypt/lib64)
[+] SSL_read  in libssl.so (com.android.conscrypt/lib64)
[*] ssl_hook.js v3 ready — 只显示评论/有效内容，过滤心跳噪音
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
... （约 1~2 秒后，B站自带 libssl.so 加载）
[+] SSL_write in libssl.so (tv.danmaku.bili-.../lib/arm64)
[+] SSL_read  in libssl.so (tv.danmaku.bili-.../lib/arm64)
```

---

## 十三、关键文件说明

| 文件 | 用途 | 状态 |
|------|------|------|
| `bypass.js` | 绕过 libmsaoaidsec.so，必须最先加载 | ✅ 使用 |
| `ssl_hook.js` | 主体：Hook SSL，解析 H2 + gRPC + REST | ✅ 使用 |
| `find_ssl.js` | 诊断工具：枚举所有 libssl.so | 诊断用 |
| `debug_pthread.js` | 诊断工具：追踪 pthread_create 来源 | 诊断用 |
| `grpc_intercept.js` | Java 层 OkHttp Hook（ART 检测秒杀）| ❌ 废弃 |
| `bypass_v5.js` | 盲化策略（read hook 导致 SIGSEGV）| ❌ 废弃 |

---

## 十四、技术总结

### 知识点一：ART Hook vs Native Hook

| 维度 | ART Hook（Java.perform）| Native Hook（Interceptor.attach）|
|------|--------------------------|----------------------------------|
| 操作对象 | ART 方法表（Java 层）| C 函数地址（Native 层）|
| 被检测风险 | **高**：B站会扫描方法表 | **低**：难以检测 |
| 适用场景 | 无检测的 App | 高对抗 App |

### 知识点二：先用控制变量法，不要乱猜

遇到莫名崩溃，正确做法：
1. 把所有脚本拆开，一个个测试
2. 找到最小复现：哪个文件加上就崩，哪个文件去掉就稳
3. 再分析这个文件里哪行代码触发了检测

本次：`bypass.js + debug_pthread.js` 稳定 → `bypass.js + grpc_intercept.js` 崩溃 → 问题在 grpc_intercept.js 的 `Java.perform`

### 知识点三：同一 App 可能有多套 SSL 库

必须同时 hook 两套：
- 系统 Conscrypt（`/apex/.../libssl.so`）
- App 自带 BoringSSL（`lib/arm64/libssl.so`）

延迟加载的库用轮询捕获（每 500ms 检查一次，共 10 秒）。

### 知识点四：z_stream 大小精确匹配

`inflateInit2_` 第四个参数必须是 `sizeof(z_stream)` = **112**（ARM64 Android），传错了会静默失败。数据有 gzip magic bytes（`1f 8b`）但解压失败，多半是这个原因。

### 知识点五：HTTP/2 DATA 帧不等于 gRPC

同一条 HTTP/2 连接上，DATA 帧可能是 gRPC（gc=0/1 header + Protobuf），也可能是普通 REST body（直接是表单数据）。不能只处理 gc=0/1 的情况，否则会漏掉 REST 流量。

---

## 十五、后续方向

### 分析 sign 签名算法

```
sign=83f5e24c3e2a92761f06d274ff412fb2
```

已知这是 MD5，下一步：
1. 在 libignet.so 或 smali 代码中搜索 `appSecret`、`appsecret` 相关字符串
2. Hook MD5 计算函数，追踪输入字符串
3. 复现签名算法，用 Python 直接调用 B站 API

### TLS Session Key 导出（Wireshark 解密）

Hook BoringSSL 的密钥回调接口，导出 `SSLKEYLOGFILE` 格式的密钥文件，在 Wireshark 里解密 pcap。这样可以用 Wireshark 的完整分析工具链，所有流量都可见。

---

## 参考资料

- [frida_环境搭建与bilibili绕过.md](./frida_环境搭建与bilibili绕过.md)
- [bilibili_grpc_抓包分析.md](./bilibili_grpc_抓包分析.md)
- [HTTP/2 RFC 7540 - Frame Format](https://httpwg.org/specs/rfc7540.html)
- [gRPC over HTTP/2 协议规范](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- [zlib 手册 - inflateInit2](https://www.zlib.net/manual.html)

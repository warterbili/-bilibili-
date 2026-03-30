# B站评论接口完整逆向记录

> **前置文档**：
> - [frida_环境搭建与bilibili绕过.md](./frida_环境搭建与bilibili绕过.md) — Frida 环境 + bypass.js
> - [bilibili_grpc_抓包分析.md](./bilibili_grpc_抓包分析.md) — tcpdump + gRPC 协议发现
> - [bilibili_ssl明文拦截_技术实录.md](./bilibili_ssl明文拦截_技术实录.md) — SSL Hook + 明文流量捕获
> - [bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md) — sign 算法还原
>
> **分析日期**：2026-02-20
> **设备**：小米 9（cepheus），PixelExperience 13.0，Frida 17.7.3，B站 v8.83.0

---

## 一、目标

把 B站发评论的完整请求格式记录下来，包括：
- HTTP/2 请求头（HPACK 解码后的完整头字段）
- 请求体（所有参数）
- 响应格式
- sign 签名验证

最终目标：掌握足够信息，能用 Python 伪造合法的评论请求。

---

## 二、抓包工具链

### 工具栈

```
手机端：frida-server 17.7.3（/data/local/tmp/frida-server）
PC 端：frida-tools 17.7.3（pip install frida-tools）
脚本：bypass.js（绕过反检测）+ capture_comment.js（抓包）
```

### 运行指令

```bash
frida -U -f tv.danmaku.bili \
  -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" \
  -l "C:/lsd_project/app_reverse/bilibili_frida绕过/capture_comment.js"
```

### 预期启动输出

```
[*] Fake function @ 0x7...
[+] dlsym real address: 0x786ce8d044
[+] dlsym hooked successfully
[*] bypass ready
[*] capture_comment.js v3 ready — Huffman + 动态表解码已启用
[*] 等待发评论，会打印完整 HEADERS + BODY + RESPONSE
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
... （等 B站自带 libssl.so 加载）
[+] Hooked libssl.so (com.android.conscrypt/lib64/libssl.so)
[+] Hooked libssl.so (tv.danmaku.bili-.../lib/arm64/libssl.so)
```

看到两个 libssl.so 都 Hooked 后，打开视频发一条评论即可。

---

## 三、抓包过程中的技术挑战

### 3.1 第一版 ssl_hook.js：能抓 body，抓不到请求头

最初的 `ssl_hook.js` 能解析 HTTP/2 DATA 帧（请求体），但对 HEADERS 帧束手无策：

```
→ SEND api.bilibili.com [DATA stream=21 897B REST-BODY]
  access_key=...
  message=%E5%93%88%E5%93%88
  sign=83f5e24c...
```

body 全部拿到了，但 `content-type`、`user-agent`、`x-bili-*` 这些请求头一个都看不到。

**原因：HPACK 压缩**

HTTP/2 的请求头不是明文传输的，而是用 HPACK 协议压缩：

```
HTTP/1.1（明文）：
  Content-Type: application/x-www-form-urlencoded\r\n
  User-Agent: Mozilla/5.0 ...\r\n

HTTP/2（HPACK 压缩）：
  0x82 0x86 0x44 0x88 0x62 0xa1 ...  ← 二进制，人眼不可读
```

HPACK 有两个机制让解码变得困难：
1. **Huffman 编码**：字符串用变长 Huffman 码压缩，比如 `application` 编码后只有几个字节
2. **动态表**：重复出现的头字段只传索引号，不传完整值

---

### 3.2 第二版 capture_comment.js v1：加了静态表，但 Huffman 不行

实现了 HPACK 静态表查找（61 个预定义头字段），但 Huffman 编码的值显示为 `[huff NB]`：

```
← RECV api.bilibili.com [HEADERS stream=21 flags=0x4]
  :status: 200
  date: [huff 22B]              ← 无法解码
  content-type: [huff 22B]      ← 无法解码
```

**问题**：HPACK Huffman 编码使用 RFC 7541 Appendix B 定义的 257 个符号的变长编码表。不实现这张表就无法解码任何字符串值。

更严重的是：**请求 HEADERS 帧被整体跳过了**。因为请求头里几乎所有值都是 Huffman 编码的，解码函数返回空数组，被 `if (hdrs.length > 0)` 过滤掉了。

---

### 3.3 第三版 capture_comment.js v2：实现了 Huffman 解码

将 RFC 7541 Appendix B 的完整 Huffman 编码表（257 个符号的 code + bitLength）嵌入脚本，启动时构建二叉解码树：

```javascript
// 257 个符号的 Huffman 编码，启动时构建解码树
var _HCODES = [0x1ff8, 0x7fffd8, 0xfffffe2, ...]; // 编码值
var _HBITS  = [13, 23, 28, ...];                   // 位长度

// 构建二叉树：沿 bit 路径走到叶节点 = 解码出一个字符
var _huffRoot = [null, null];
for (sym = 0; sym <= 256; sym++) {
    // 把每个符号的编码路径插入树中
    ...
}
```

这次请求头出来了，但很多字段显示为 `[dynidx N]`：

```
🔴 → SEND api.bilibili.com [HEADERS stream=23 flags=0x4]
  [dynidx 99]           ← ？
  :method: POST         ← 静态表，正常
  :path: /x/v2/reply/add ← 本帧新传的值，正常
  :scheme: https        ← 静态表，正常
  [dynidx 77]           ← ？
  [dynidx 76]           ← ？
  content-length: 900   ← 本帧新传的值，正常
  [dynidx 69]           ← ？
```

**原因：HPACK 动态表**

HTTP/2 在一条连接上的所有请求共享一个"动态表"。工作方式：

```
第 1 个请求（如首页 API）：
  HEADERS 帧完整传输：content-type: application/json
  → 编码器同时把 [content-type, application/json] 存入动态表索引 #62

第 2 个请求（如视频信息）：
  HEADERS 帧完整传输：content-type: application/x-www-form-urlencoded
  → 存入动态表索引 #62（原来的变成 #63）

第 N 个请求（发评论，stream=23）：
  HEADERS 帧只传索引号：#77
  → 需要查动态表才知道 #77 是什么
```

B站 App 启动后在发评论之前已经发了十几个请求（首页、视频信息、搜索等），动态表里已经积累了几十个条目。v2 没有跟踪这张表，所以那些索引查不到。

---

### 3.4 第四版 capture_comment.js v3：加了动态表跟踪

给 HPACK 解码器加上动态表维护：

```javascript
// 每个 connection+direction 维护独立的动态表
var _dynTables = {};
function getDynTable(host, dir) {
    var key = (host || "?") + "|" + dir;
    if (!_dynTables[key]) _dynTables[key] = [];
    return _dynTables[key];
}
```

关键逻辑：
- **增量索引**（`0x40` 前缀）：解码 name+value 后，`dynTable.unshift([name, val])` 加入表头
- **索引查找**（`0x80` 前缀）：`idx < 62` 查静态表，`idx >= 62` 查 `dynTable[idx - 62]`
- **不索引**（`0x00`/`0x10` 前缀）：只解码，不加入动态表

因为用 spawn 模式注入（`-f tv.danmaku.bili`），脚本在 App 任何代码执行前就已就绪，能捕获连接上的**所有** HEADERS 帧，动态表从零开始完整累积。

**终于拿到了完整的请求头。**

---

## 四、完整请求格式

### 4.1 请求头（HTTP/2 HEADERS 帧）

```
:authority: api.bilibili.com
:method: POST
:path: /x/v2/reply/add
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br
app-key: android64
bili-http-engine: ignet
buvid: XU851958B8BC3412258E291F5D3152432F1CA
content-length: 885
content-type: application/x-www-form-urlencoded; charset=utf-8
env: prod
fp_local: 0fcca6e89ccb4cb6b3444f3fbf2d5c78202602182227205b2919c0a28bf73a9b
fp_remote: 0fcca6e89ccb4cb6b3444f3fbf2d5c78202602182227205b2919c0a28bf73a9b
guestid: 25884827183574
session_id: d474c56e
user-agent: Mozilla/5.0 BiliDroid/8.83.0 (bbcallen@gmail.com) 8.83.0 os/android model/MI 9 mobi_app/android build/8830500 channel/html5_search_google innerVer/8830510 osVer/13 network/2
x-bili-aurora-eid: VVcER1cHAlYO
x-bili-locale-bin: Cg4KAnpoEgRIYW5zGgJDThIICgJ6aBoCQ04iDUFzaWEvU2hhbmdoYWkqBiswODowMA
x-bili-metadata-ip-region: CN
x-bili-metadata-legal-region: CN
x-bili-mid: 435163479
x-bili-trace-id: CAEqEQ03fH4/EOCf3AQYjNvotccz
x-bili-redirect: 1
x-bili-ticket: eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzE1NDA1OTYsImlhdCI6MTc3MTUxMTQ5NiwiYnV2aWQiOiJYVTg1MTk1OEI4QkMzNDEyMjU4RTI5MUY1RDMxNTI0MzJGMUNBIn0.Aur-9tdOaITVqNZcqkj3N41KNT8P4-4nIRruIGTZcws
```

#### 头字段分类说明

| 分类 | 字段 | 说明 |
|------|------|------|
| **HTTP/2 伪头** | `:authority`, `:method`, `:path`, `:scheme` | 标准 HTTP/2 必须字段 |
| **标准头** | `accept`, `accept-encoding`, `content-type`, `content-length`, `user-agent` | 通用 HTTP 头 |
| **App 标识** | `app-key=android64`, `bili-http-engine=ignet` | 标识来源 App 和网络库 |
| **设备指纹** | `buvid`, `fp_local`, `fp_remote`, `guestid` | 设备唯一标识，反作弊用 |
| **会话** | `session_id`, `x-bili-ticket` (JWT) | 会话认证 |
| **用户** | `x-bili-mid=435163479` | 当前登录用户 UID |
| **地区** | `x-bili-metadata-ip-region`, `x-bili-metadata-legal-region`, `x-bili-locale-bin` | 地区/语言信息 |
| **追踪** | `x-bili-aurora-eid`, `x-bili-trace-id`, `x-bili-redirect` | 流量追踪 |
| **环境** | `env=prod` | 生产环境 |

#### x-bili-ticket 解码

`x-bili-ticket` 是标准 JWT（JSON Web Token），Base64 解码 payload 部分：

```json
{
  "exp": 1771540596,
  "iat": 1771511496,
  "buvid": "XU851958B8BC3412258E291F5D3152432F1CA"
}
```

有效期约 8 小时（`exp - iat = 29100` 秒）。包含 buvid 设备指纹，用于关联设备和会话。

#### user-agent 格式

```
Mozilla/5.0 BiliDroid/{版本号} (bbcallen@gmail.com) {版本号}
os/android model/{设备型号} mobi_app/android build/{build号}
channel/{渠道} innerVer/{内部版本} osVer/{安卓版本} network/{网络类型}
```

`network` 值：`2` = Wi-Fi（推测，基于测试环境）

---

### 4.2 请求体（HTTP/2 DATA 帧）

Content-Type: `application/x-www-form-urlencoded; charset=utf-8`

URL 编码的键值对，按 `&` 分隔：

```
access_key=9268870d42b7212148710905156f8721CjBAOXQg...（OAuth token）
appkey=1d8b6e7d45233436
build=8830500
c_locale=zh-Hans_CN
channel=html5_search_google
container_uuid=4866a0c3-c05d-4ecf-bcf9-d663452d16ce
disable_rcmd=0
from_spmid=tm.recommend.0.0
has_vote_option=false
message=%5B%E7%AC%91%E5%93%AD%5D
mobi_app=android
oid=116083721768888
ordering=heat
plat=2
platform=android
s_locale=zh-Hans_CN
scene=main
scm_action_id=E89F0ACA
spmid=united.player-video-detail.0.0
statistics=%7B%22appId%22%3A1%2C%22platform%22%3A3%2C%22version%22%3A%228.83.0%22%2C%22abtest%22%3A%22%22%7D
sync_to_dynamic=false
track_id=all_0.router-pegasus-2479124-2dxd2.1771518418621.379
ts=1771518449
type=1
sign=75dfbb297d4634ee9d60804e170fa557
```

#### 参数分类说明

| 分类 | 参数 | 说明 |
|------|------|------|
| **核心参数** | `message` | 评论内容（URL 编码）|
| | `oid` | 目标视频/内容 ID |
| | `type` | 内容类型（`1`=视频评论） |
| **认证** | `access_key` | OAuth token（很长，含加密信息） |
| | `appkey` | 应用标识符 `1d8b6e7d45233436` |
| **App 信息** | `build`, `mobi_app`, `platform`, `channel` | App 版本和渠道 |
| **地区** | `c_locale`, `s_locale` | 客户端/服务端语言 |
| **界面上下文** | `from_spmid`, `spmid`, `scene`, `ordering` | 来源页面、排序方式 |
| **追踪** | `container_uuid`, `scm_action_id`, `track_id` | 行为追踪 |
| **时间** | `ts` | Unix 时间戳（秒） |
| **其他** | `disable_rcmd`, `has_vote_option`, `sync_to_dynamic`, `plat`, `statistics` | 功能开关和统计 |
| **签名** | `sign` | MD5 签名（防篡改） |

#### message 编码示例

| 原文 | URL 编码 |
|------|---------|
| 哈哈 | `%E5%93%88%E5%93%88` |
| [笑哭] | `%5B%E7%AC%91%E5%93%AD%5D` |

B站表情用方括号文本格式传输，不是 emoji。

---

### 4.3 响应格式

HTTP/2 HEADERS + DATA：

**响应头：**
```
:status: 200
content-type: application/json; charset=utf-8
```

**响应体（gzip 压缩，解压后 JSON）：**

```json
{
  "code": 0,
  "message": "OK",
  "ttl": 1,
  "data": {
    "rpid": 290501715345,
    "rpid_str": "290501715345",
    "reply": {
      "rpid": 290501715345,
      "oid": 115621979232790,
      "type": 1,
      "mid": 435163479,
      "ctime": 1771517477,
      "member": {
        "uname": "G......",
        "avatar": "https://i0.hdslb.com/bfs/face/..."
      }
    }
  }
}
```

| 字段 | 说明 |
|------|------|
| `code` | 0 = 成功 |
| `rpid` | 新评论的 ID |
| `oid` | 视频 ID（与请求一致） |
| `mid` | 评论者 UID |
| `ctime` | 发布时间戳（与请求 `ts` 一致） |

---

## 五、sign 签名算法

### 5.1 算法说明

sign 是防篡改签名，确保请求参数没有被中间人修改。

**计算步骤：**

```
1. 取所有参数（不含 sign 本身）
2. 按 key 字母序排列
3. 每个 value 做 URL 编码（quote(v, safe='')）
4. 拼接为 "key1=encoded_val1&key2=encoded_val2&..."
5. MD5_Update(sorted_params)
6. MD5_Update("560c52cc")    ← appSecret[0] 的 %08x 输出
7. MD5_Update("d288fed0")    ← appSecret[1]
8. MD5_Update("45859ed1")    ← appSecret[2]
9. MD5_Update("8bffd973")    ← appSecret[3]
10. MD5_Final → 32 字符小写 hex
```

appSecret = `560c52ccd288fed045859ed18bffd973`

### 5.2 两种等价实现

**逆向方案（bili_sign.py）**— 忠实还原 libbili.so 的实际执行逻辑：

```python
import hashlib
from urllib.parse import quote

_SECRET_UINT32 = [0x560c52cc, 0xd288fed0, 0x45859ed1, 0x8bffd973]

def make_sign(params: dict) -> str:
    sorted_params = "&".join(
        f"{k}={quote(str(v), safe='')}"
        for k, v in sorted(params.items())
    )
    ctx = hashlib.md5()
    ctx.update(sorted_params.encode("utf-8"))
    for v in _SECRET_UINT32:
        ctx.update(("%08x" % v).encode("utf-8"))
    return ctx.hexdigest()
```

**公开方案（bili_sign_opensource.py）**— 网上流传的简化写法：

```python
def make_sign(params: dict, secret="560c52ccd288fed045859ed18bffd973") -> str:
    sorted_params = "&".join(
        f"{k}={quote(str(v), safe='')}"
        for k, v in sorted(params.items())
    )
    return hashlib.md5((sorted_params + secret).encode("utf-8")).hexdigest()
```

**为什么结果一样：**

```
MD5_Update(A) + MD5_Update(B) = MD5(A + B)
sprintf("%08x", 0x560c52cc) + ... = "560c52ccd288fed045859ed18bffd973"
```

流式更新等价于拼接，4 个 uint32 的 %08x 输出拼起来就是 secret 字符串。数学上完全等价。

**为什么 libbili.so 要用 uint32 而不是直接存字符串：**

防字符串搜索。`strings libbili.so | grep "560c52cc"` 找不到任何东西，因为内存里存的是二进制整数 `cc 52 0c 56 ...`，不是可读文本。格式字符串 `"%08x"` 还被 `datadiv_decode` 额外加密，必须动态分析才能确认。

### 5.3 验证结果

用 3 组不同的抓包数据验证：

| 数据 | message | oid | 抓包 sign | 逆向 | 公开 |
|------|---------|-----|-----------|------|------|
| #1 | 哈哈 | 116063807212606 | `83f5e24c...` | ✅ | ✅ |
| #2 | 哈哈 | 115621979232790 | `f7caaf24...` | ✅ | ✅ |
| #3 | [笑哭] | 116083721768888 | `75dfbb29...` | ✅ | ✅ |

不同视频、不同内容、不同时间戳，全部匹配。算法稳定可靠。

---

## 六、Frida 脚本说明

### 6.1 bypass.js — 绕过反 Frida 检测

**路径**：`bilibili_frida绕过/bypass.js`

Hook `dlsym`，当 `libmsaoaidsec.so` 查询 `pthread_create` 时返回假函数，阻止检测线程启动。

```bash
# 单独使用（只绕过检测，进入 REPL）
frida -U -f tv.danmaku.bili -l bypass.js
```

### 6.2 capture_comment.js v3 — 完整请求抓包

**路径**：`bilibili_frida绕过/capture_comment.js`

Hook 两套 `libssl.so`（系统 Conscrypt + B站自带 BoringSSL）的 `SSL_write` / `SSL_read`，解析 HTTP/2 帧。

**核心能力：**
- HPACK Huffman 解码（RFC 7541 完整 257 符号编码表）
- HPACK 动态表跟踪（per connection+direction）
- HTTP/2 DATA 帧解析（gzip 解压 + URL 编码参数分行显示）
- 只显示 bili 相关流量，过滤噪音

```bash
# 抓完整评论请求（HEADERS + DATA + 响应）
frida -U -f tv.danmaku.bili -l bypass.js -l capture_comment.js
```

### 6.3 ssl_hook.js v3 — 通用 SSL 流量监控

**路径**：`bilibili_frida绕过/ssl_hook.js`

更早期的版本，功能：
- gRPC Protobuf 解析
- REST body 解析
- gzip 解压
- 不含 HPACK 动态表（请求头会有 `[dynidx]`）

```bash
# 通用流量监控（gRPC + REST 都看）
frida -U -f tv.danmaku.bili -l bypass.js -l ssl_hook.js
```

### 6.4 sign 验证脚本

```bash
# 验证 sign 算法
cd C:\lsd_project\app_reverse\sign_verify
python verify_both.py
```

| 文件 | 用途 |
|------|------|
| `bili_sign.py` | 逆向还原的 sign 模块（可复用） |
| `bili_sign_opensource.py` | 公开方案的 sign 模块（可复用） |
| `verify_both.py` | 用抓包数据验证两个方案 |
| `sign_from_reverse.py` | 逆向过程文档 + 验证用例 |

---

## 七、完整请求链路图

```
用户点击"发送"
    │
    ▼
App 构建参数 dict
    │  message="哈哈", oid=116083721768888, ts=当前时间, ...
    │
    ▼
libbili.so 计算 sign
    │  FUN_00109050 → FUN_001162a8 → FUN_00118ff0
    │  MD5(sorted_url_encoded_params + appSecret)
    │  → sign=75dfbb297d4634ee9d60804e170fa557
    │
    ▼
libignet.so 发送请求（绕过系统代理）
    │
    ├─ HEADERS 帧 ──→ :method:POST :path:/x/v2/reply/add
    │                   content-type, user-agent, x-bili-*, ...
    │
    ├─ DATA 帧 ────→ access_key=...&message=%E5%93%88...&sign=75dfbb...
    │
    ▼
libssl.so（B站自带 BoringSSL）
    │  SSL_write(明文) → TLS 加密 → 网卡发出密文
    │            ↑
    │     Frida hook 在这里截获明文
    │
    ▼
api.bilibili.com 服务器
    │
    ▼ 响应
{"code":0, "rpid":290501715345, ...}
```

---

## 八、关键发现总结

### 为什么 Charles 抓不到评论

```
OkHttp（Java 层）→ 走系统代理 → Charles 能看到
libignet.so（C++ 层）→ 直接 TCP，无视代理 → Charles 完全看不到

评论发送走 libignet.so → Charles 无能为力
```

### 评论发送 ≠ gRPC

```
评论发送：POST /x/v2/reply/add → api.bilibili.com（REST）
评论接收：service_comment 订阅 → grpc.biliapi.net（gRPC Stream）
```

同一个功能（评论）的读写分属两个完全不同的协议和端点。

### B站有两套 libssl.so

```
系统 Conscrypt：/apex/com.android.conscrypt/lib64/libssl.so → OkHttp 用
B站自带：/data/app/.../tv.danmaku.bili-.../lib/arm64/libssl.so → libignet.so 用
```

必须两个都 hook。B站的 libssl.so 延迟加载（第一次网络请求时才 dlopen），需要轮询检测。

### HPACK 解码需要三层能力

| 层 | 功能 | 不实现的后果 |
|----|------|-------------|
| 静态表 | 61 个预定义头字段 | `:method`、`:status` 等基础头丢失 |
| Huffman | 257 符号变长编码 | 所有字符串值变成 `[huff NB]` |
| 动态表 | 连接级别的头字段缓存 | 大量头显示为 `[dynidx N]` |

三层都实现后才能完整解码 HTTP/2 请求头。

---

## 九、文件索引

### Frida 脚本（bilibili_frida绕过/）

| 文件 | 用途 | 状态 |
|------|------|------|
| `bypass.js` | 绕过 libmsaoaidsec.so 反检测 | ✅ 必须 |
| `capture_comment.js` | 完整请求抓包（HPACK + 动态表） | ✅ 使用 |
| `ssl_hook.js` | 通用 SSL 流量监控 | ✅ 使用 |
| `find_ssl.js` | 枚举所有 libssl.so | 诊断用 |
| `diagnose.js` | 排查 hook 问题 | 诊断用 |
| `find_registernatives.js` | 找 RegisterNative 符号名 | 诊断用 |
| `hook_sign.js` | 捕获 native 方法地址 | 逆向用 |
| `hook_appsecret.js` | 读取 appSecret | 逆向用 |
| `hook_sprintf.js` | 确认加密格式字符串 | 逆向用 |
| `debug_pthread.js` | 追踪 pthread_create 来源 | 诊断用 |
| `grpc_intercept.js` | Java 层 Hook（被 ART 检测秒杀） | ❌ 废弃 |
| `bypass_v5.js` | 盲化策略（SIGSEGV 崩溃） | ❌ 废弃 |

### Python 脚本（sign_verify/）

| 文件 | 用途 |
|------|------|
| `bili_sign.py` | sign 算法模块 — 逆向还原版（可复用） |
| `bili_sign_opensource.py` | sign 算法模块 — 公开方案版（可复用） |
| `verify_both.py` | 用抓包数据对比验证两个方案 |
| `sign_from_reverse.py` | 逆向文档 + 验证入口 |

---

> 相关文档：
> [frida_环境搭建与bilibili绕过.md](./frida_环境搭建与bilibili绕过.md) ·
> [bilibili_grpc_抓包分析.md](./bilibili_grpc_抓包分析.md) ·
> [bilibili_ssl明文拦截_技术实录.md](./bilibili_ssl明文拦截_技术实录.md) ·
> [bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md)

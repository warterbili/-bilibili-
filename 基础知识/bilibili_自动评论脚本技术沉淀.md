# B站自动评论脚本 — 技术沉淀

> **前置文档**：
>
> - [bilibili_评论接口完整逆向记录.md](./bilibili_评论接口完整逆向记录.md) — 完整的请求头/请求体/sign 验证
> - [bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md) — sign 算法还原
>
> **日期**：2026-02-20
> **代码目录**：`auto_comment/`（与 `sign_verify/` 平级）

---

## 一、整体思路

逆向工作分了两个阶段：

| 阶段                         | 工作                                                                            | 成果                                |
| ---------------------------- | ------------------------------------------------------------------------------- | ----------------------------------- |
| **逆向阶段**（已完成） | Frida hook libssl/libignet，抓明文 HTTP/2；Ghidra 静态分析 libbili.so 还原 sign | 27 个请求头 + 24 个参数 + sign 算法 |
| **工程化阶段**（本文） | 把逆向成果整合成可运行的 Python 脚本                                            | `auto_comment/` 目录下 4 个文件   |

工程化阶段的核心挑战不是"写代码"，而是**处理逆向中没覆盖到的环节** —— 主要是 `x-bili-ticket` 的获取。

---

## 二、x-bili-ticket 获取方案

### 2.1 问题背景

抓包得到的 27 个请求头里有一个 `x-bili-ticket`，值是 JWT 格式：

```
eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzE1NDA1OTYsImlhdCI6MTc3MTUxMTQ5NiwiYnV2aWQiOiJYVTg1MTk1OEI4QkMzNDEyMjU4RTI5MUY1RDMxNTI0MzJGMUNBIn0.Aur-9tdOaITVqNZcqkj3N41KNT8P4-4nIRruIGTZcws
```

JWT 解码后 payload：

```json
{
  "exp": 1771540596,
  "iat": 1771511496,
  "buvid": "XU851958B8BC3412258E291F5D3152432F1CA"
}
```

这个 ticket 会过期（JWT exp 约 8 小时），硬编码抓包值不可行，必须实现自动刷新。

### 2.2 JWT 完整知识

#### JWT 像什么？—— 一张盖了公章的证明信

```
你去银行办业务，柜员说"你是谁？证明一下"

方案 A：每次都打电话给你公司核实 → 慢，公司电话打爆
方案 B：公司给你开一张证明信，盖了公章 → 银行看一眼章就信了
```

JWT 就是那张**盖了章的证明信**。

#### JWT 的三个部分

```
eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MzUxNjM0NzkifQ.XXXXXXXXXXXX
|______ Header ______| |________ Payload ________| |__ Signature __|
       信封                    信的内容                  公章
```

| 部分                | 内容                        | 类比                                      |
| ------------------- | --------------------------- | ----------------------------------------- |
| **Header**    | 算法类型、密钥 ID           | 信封上写着"这个章是用哪个印章盖的"        |
| **Payload**   | 业务数据（uid、过期时间等） | 信的正文："张三是我公司员工，有效期到 xx" |
| **Signature** | 签名值                      | 公章本身                                  |

三部分都是 Base64 编码，用 `.` 连接。任何 JWT 都可以直接解码看内容：

```python
import base64, json
jwt_str = "eyJhbGci..."
payload = jwt_str.split('.')[1] + '=='
print(json.loads(base64.urlsafe_b64decode(payload)))
```

就是这样算出 B站 ticket 的 `exp - iat = 29100秒 ≈ 8.1小时` 的。

#### 为什么需要 JWT？

没有 JWT 的世界：

```
用户登录后每次请求：
  客户端 → "我是 uid=435163479" → 服务端
  服务端 → 查数据库确认这个用户是否登录 → 返回数据

问题：每次请求都要查数据库/Redis，10 万用户同时在线，数据库扛不住
```

有 JWT 的世界：

```
登录时：
  服务端 → 生成 JWT（写入 uid + 过期时间 + 签名）→ 返给客户端

后续每次请求：
  客户端 → 带上 JWT → 服务端
  服务端 → 验证签名（纯计算，不查库）→ 签名对了就信任 payload 里的 uid

好处：服务端不存状态，不查库，纯算法验证，极快
```

#### 签名算法是什么意思？

Header 里的 `"alg": "HS256"` 就是签名算法：

```python
signature = HMAC_SHA256(密钥, Header_Base64 + "." + Payload_Base64)
```

**签名的作用是防篡改**：

```
你把 JWT 里的 uid 从 435163479 改成 000000001（想冒充管理员）
→ payload 变了，但你不知道密钥，算不出新的 signature
→ 服务端验签：signature 和 payload 对不上 → 拒绝
```

常见的签名算法：

| 算法            | 类型               | 密钥                                 |
| --------------- | ------------------ | ------------------------------------ |
| **HS256** | 对称（HMAC）       | 服务端有一个密钥，签名和验证用同一个 |
| **RS256** | 非对称（RSA）      | 私钥签名，公钥验证                   |
| **ES256** | 非对称（椭圆曲线） | 私钥签名，公钥验证                   |

#### 密钥是什么？在哪里？

密钥就是一串只有服务端知道的字符串，**永远不会出现在 JWT 里**。

```
举例：B站服务端有一个密钥 = "s3cRetKey_xyz_123"（假设的）

签名时：
  signature = HMAC_SHA256("s3cRetKey_xyz_123", header + "." + payload)

JWT 发给客户端：
  header.payload.signature    ← 只有签名结果，密钥本身不在里面

验签时：
  服务端用同一个密钥重新算一遍，对比 signature 是否一致
```

类比：

```
公章 = signature（盖在纸上的印记，所有人可见）
印章 = 密钥（锁在服务端保险柜里，没人能拿到）

你能看到纸上的公章长什么样 → 但你造不出那个印章
```

#### 为什么把算法公开写在 Header 里？隐藏起来不是更安全？

直觉上"隐藏算法更安全"，但实际上**隐藏算法不会更安全，反而造成麻烦**。

**原因 1：安全性靠密钥，不靠隐藏算法（Kerckhoffs 原则）**

这是密码学的基本原则：

```
❌ 错误思路：算法保密 → 安全
✅ 正确思路：算法公开，密钥保密 → 安全
```

现实例子：

```
AES 加密算法 → 全世界公开的，论文随便看
但至今没人能破解 → 因为安全性来自密钥，不来自算法本身

如果一个系统的安全性依赖"没人知道我用了什么算法"
→ 一旦算法泄露（离职员工、逆向），整个系统就崩了
→ 而且没法换算法，因为所有客户端都要改
```

**原因 2：服务端需要知道用什么算法来验签**

同一个服务可能同时存在多种算法的 JWT：

```
2024 年发的 JWT → 用 HS256 签名
2025 年升级后  → 新发的 JWT 用 RS256 签名
但 2024 年的旧 JWT 还没过期，也要能验证
```

服务端收到 JWT，怎么知道用哪个算法验？**看 Header**：

```json
{"alg": "HS256", "kid": "s03"}
                        ↑
              密钥 ID：告诉服务端用 s03 号密钥来验
```

不写算法就得挨个试：先试 HS256，不对再试 RS256，再试 ES256…… 这就乱了。

**原因 3：知道算法也没用**

```
你知道了：alg = HS256
你知道了：payload = {"uid": "435163479", "exp": 1771540596}
你想伪造一个 uid = 000000001 的 JWT

你需要算：HMAC_SHA256(???, new_header + "." + new_payload)
                       ↑
                  密钥你不知道 → 算不出来 → 伪造失败
```

#### JWT 为什么不是加密的？

**因为不需要。** JWT 解决的问题是"证明你是谁"，不是"隐藏你是谁"。

```
盖章的证明信：
  ✅ 任何人都能看内容 → "张三，工号 123，有效期到 xx"
  ✅ 但没人能伪造公章 → 篡改内容后章就对不上了
  ❌ 不需要把信放保险箱 → 信的内容本来就不是秘密
```

|        | 加密             | 签名（JWT）                        |
| ------ | ---------------- | ---------------------------------- |
| 目的   | 隐藏内容，防窃听 | 防篡改，证明身份                   |
| 谁能看 | 只有持密钥的人   | **任何人都能看**             |
| 谁能改 | 只有持密钥的人   | **任何人都改不了**（没密钥） |

> 所以 JWT payload 里**不应该放密码、手机号等敏感信息**，因为谁都能 Base64 解码看到。
> 如果确实需要加密 JWT 内容，有一个扩展标准叫 **JWE**（JSON Web Encryption），但实际很少用。

#### 回到 B站的场景

```
B站 x-bili-ticket 的生命周期：

1. App 调 GenWebTicket 接口 → 服务端返回 JWT（签名密钥在服务端）
2. App 每次请求带上这个 JWT 作为 header
3. B站服务端收到请求 → 验签名 → 签名对了就信任里面的 buvid
4. 不需要每次都查库确认 buvid 是否合法，纯计算验证
5. 过期了（exp 到了）→ 重新请求一个新的
```

### 2.3 判断 JWT 来源：服务端下发 vs 写死 vs 本地生成

拿到一个未知 App 的 JWT，三种可能的来源：

| 来源             | 说明                         | 常见程度 |
| ---------------- | ---------------------------- | -------- |
| 服务端下发       | App 请求接口，服务端返回 JWT | 绝大多数 |
| 写死在 App 中    | 硬编码在 dex/so 里，不会变   | 极少     |
| App 本地动态生成 | 签名密钥藏在 App 里，本地算  | 少数     |

#### 判断流程

**第一步：解码 payload 看时间戳**

```python
import base64, json
payload = jwt.split('.')[1] + '=='
print(json.loads(base64.urlsafe_b64decode(payload)))
```

| 现象                          | 结论                       |
| ----------------------------- | -------------------------- |
| `iat` 是你刚打开 App 的时间 | 动态生成的（服务端或本地） |
| `iat` 是很久以前的固定值    | 可能是写死的               |
| 没有 `iat`/`exp` 字段     | 需要进一步分析             |

**第二步：重启 App，对比两次 JWT**

```
第一次启动 → 记录 JWT_A
杀掉进程 → 重新启动 → 记录 JWT_B
```

| 现象                       | 结论                     |
| -------------------------- | ------------------------ |
| JWT_A == JWT_B             | 写死的，或缓存的还没过期 |
| JWT_A != JWT_B，时间戳变了 | 动态生成（服务端或本地） |

**第三步：断网测试（区分服务端 vs 本地）**

```
1. 手机开飞行模式（彻底断网）
2. 清除 App 数据（设置 → 应用 → 清除数据）
3. 打开 App
4. Hook 或导出此时的 JWT
```

| 现象                          | 结论                 |
| ----------------------------- | -------------------- |
| 断网后拿不到新 JWT / App 报错 | **服务端下发** |
| 断网后照样拿到新 JWT          | **本地生成**   |

**第四步（可选）：反编译搜签名密钥**

如果确认是本地生成，签名密钥一定在 App 里：

```bash
# jadx 反编译后搜索
grep -r "HmacSHA256\|HMAC\|SecretKeySpec" ./jadx_output/
grep -r "HS256\|JWT\|jsonwebtoken" ./jadx_output/
```

找到密钥 → 可以自己造 JWT，连服务端接口都不用调。

#### 流程图总结

```
拿到 JWT
  │
  ├─ 解码 payload，看 iat 时间戳
  │    ├─ 固定远古值 ──────────────→ 写死的
  │    └─ 最近的时间 → 动态生成 ──┐
  │                               │
  ├─ 重启 App 对比两次 JWT        │
  │    ├─ 完全相同 → 缓存的      │
  │    └─ 不同 → 确认动态 ────────┘
  │                               │
  └─ 断网 + 清数据测试            │
       ├─ 断网拿不到 → 服务端下发 ◄┘
       └─ 断网能拿到 → 本地生成
                        │
                        └→ 反编译搜 HMAC 密钥 → 自己造
```

> B站 ticket 的情况：HS256 签名，iat 是最近时间，断网拿不到 → **服务端下发**。

### 2.4 逆向方法论：如何找到 JWT 的获取接口

通过 2.3 判断出是服务端下发后，下一步是找到具体的获取接口。
核心思路：**从使用点往回追**。

**方法 A：抓包搜 JWT 前缀**

已经 hook 了 libssl 能抓明文流量，那最直接的方式：

```
App 冷启动时开始抓包，捕获所有请求和响应
→ 搜索 "eyJ"（JWT Base64 固定前缀）
→ 找到哪个响应返回了 ticket → 就是获取接口
```

> 注意：如果 ticket 已缓存，App 可能不会请求。需要**清除 App 数据**或等 ticket 过期后再抓。

**方法 B：Hook 缓存层（无需清数据，推荐）**

即使 App 不重新请求，每次使用 ticket 都要从缓存里读。Hook 存储层就能追到完整链路：

```javascript
// Hook SharedPreferences.getString —— 捕获 JWT 缓存读取
Java.use("android.app.SharedPreferencesImpl").getString.implementation = function(key, defValue) {
    var value = this.getString(key, defValue);
    if (value && value.toString().startsWith("eyJ")) {
        console.log("[SP.getString] key=" + key);
        console.log("[SP.getString] value=" + value.toString().substring(0, 80));
        // 打印调用栈 —— 这是最关键的信息
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()
        ));
    }
    return value;
};
```

同时 hook `putString` 捕获写入：

```javascript
// Hook SharedPreferences.putString —— 捕获 JWT 写入/更新
Java.use("android.app.SharedPreferencesImpl$EditorImpl").putString.implementation = function(key, value) {
    if (value && value.toString().startsWith("eyJ")) {
        console.log("[SP.putString] key=" + key + " value=" + value.toString().substring(0, 80));
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()
        ));
    }
    return this.putString(key, value);
};
```

**调用栈会直接告诉你**：是哪个类的哪个方法读取了 ticket，顺着栈往上追就能找到网络请求层。

**方法 C：Hook Header 设置点**

补一层 HashMap.put hook，捕获 ticket 被塞进请求头 Map 的瞬间：

```javascript
Java.use("java.util.HashMap").put.implementation = function(key, value) {
    if (key !== null && key.toString() === "x-bili-ticket") {
        console.log("[HashMap.put] x-bili-ticket = " + value.toString().substring(0, 80));
        // 打印调用栈
    }
    return this.put(key, value);
};
```

> ⚠️ HashMap.put 调用量极大，务必加 key 过滤条件，否则会卡死。

#### 实操顺序总结

```
1. 先做判断：HS256 签名 → 服务端下发（不用逆 so）
2. Hook SP.getString + SP.putString，搜 "eyJ" 前缀
3. 启动 App，进任意视频页触发请求
4. 从调用栈找到 ticket 管理类
5. 在该类中找到网络请求逻辑 → 就是刷新接口
6. 抓包确认接口 URL + 参数 → Python 复现
```

> 完整的追踪脚本见 `bilibili_frida绕过/trace_ticket.js`，三层 hook 已整合。

---

### 2.5 开源情报来源（实际采用的方案）

本次实际上**没有走完上述逆向流程**，而是直接从 B站 API 社区文档中找到了 ticket 获取方式：

| 资源                                     | 链接                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **bilibili-API-collect**（主仓库） | https://github.com/SocialSisterYi/bilibili-API-collect                                           |
| bili_ticket 文档                         | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/misc/sign/bili_ticket.md |
| bili_ticket 文档（在线版）               | https://socialsisteryi.github.io/bilibili-API-collect/docs/misc/sign/bili_ticket.html            |
| APP 签名文档                             | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/misc/sign/APP.md         |
| 评论相关 API                             | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/comment/list.md          |
| bili_ticket Issue 讨论                   | https://github.com/SocialSisterYi/bilibili-API-collect/issues/903                                |

> **SocialSisterYi/bilibili-API-collect** 是目前最全的 B站第三方 API 文档，覆盖 Web/Android/iOS/TV 全平台，
> 社区持续维护中。做 B站逆向必须收藏。

### 2.6 GenWebTicket 接口详情

**端点**：

```
POST https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket
```

**两套密钥**（按平台区分）：

| 平台       | key_id   | HMAC-SHA256 密钥 |
| ---------- | -------- | ---------------- |
| Web 端     | `ec02` | `XgwSnGZ1p`    |
| Android 端 | `ec01` | `Ezlc3tgtl`    |

> 文档里公开的是 Web 端 (`ec02`)。Android 端 (`ec01`) 的密钥 `Ezlc3tgtl` 在
> 之前的对话中由 AI 从开源信息中确认（可能来自社区讨论或其他逆向项目）。

**签名计算**：

```python
import hmac, hashlib

ts = int(time.time())
hexsign = hmac.new(b"Ezlc3tgtl", f"ts{ts}".encode(), hashlib.sha256).hexdigest()
```

签名格式固定：HMAC-SHA256(密钥, `"ts" + 时间戳字符串`)。

**请求参数**（URL query string）：

| 参数            | 值                      |
| --------------- | ----------------------- |
| `key_id`      | `ec01`                |
| `hexsign`     | 上面算出来的 hex 字符串 |
| `context[ts]` | Unix 秒级时间戳         |

**响应**：

```json
{
  "code": 0,
  "data": {
    "ticket": "eyJ...",
    "created_at": 1771519929,
    "ttl": 259200
  }
}
```

- `ttl = 259200` 秒 = **3 天**（接口声明的有效期）
- 实际 JWT 中 `exp - iat ≈ 8 小时`（JWT 自身的过期时间更短）
- 脚本中以 ttl 为准，提前 5 分钟刷新

### 2.7 实测踩坑：412 WAF 拦截

第一次调用 GenWebTicket 时返回了 **HTTP 412**，响应是 HTML 风控页面。

**原因**：B站 CDN/WAF 对没有 User-Agent 的请求直接拦截。

**解决**：请求时携带 B站 App 的 UA 即可通过：

```python
headers = {
    "User-Agent": "Mozilla/5.0 BiliDroid/8.83.0 (bbcallen@gmail.com) ..."
}
resp = httpx.post(url, params=params, headers=headers, timeout=10)
```

> **教训**：B站几乎所有 API 都需要 UA，裸请求必被 412。后续写新接口时默认带 UA。

---

## 三、sign 算法与 body 编码一致性

### 3.1 核心要点

sign 的计算过程中，value 会被 `urllib.parse.quote(str(v), safe='')` 编码。
所以发送请求时的 body 编码**必须与 sign 计算完全一致**，否则服务端验签失败。

**错误做法**：用 `httpx.post(url, data=dict)` —— httpx 内部的编码行为可能与 `quote(safe='')` 不同。

**正确做法**：手工编码后用 `content=` 发送原始 bytes：

```python
from urllib.parse import quote

# 与 bili_sign.py 中 make_sign() 完全相同的编码方式
body = "&".join(
    f"{k}={quote(str(v), safe='')}"
    for k, v in sorted(signed_params.items())
)
resp = client.post(url, content=body.encode("utf-8"), headers=headers)
```

### 3.2 sign 算法回顾

详见 `sign_verify/bili_sign.py`，核心路径：

```
参数 dict
  → 按 key 排序
  → value URL 编码（quote safe=''）
  → 拼接为 "k1=v1&k2=v2&..."
  → MD5 streaming: update(sorted_str) + update(appSecret 4×uint32 展开)
  → hexdigest → 32 字符小写 hex
```

appkey = `1d8b6e7d45233436`，appSecret = `560c52ccd288fed045859ed18bffd973`

---

## 四、请求头构造策略

### 4.1 初版策略：全量携带

抓包拿到 27 个头，初版全部硬编码/动态生成，确保与真实 App 请求一致。

### 4.2 各头字段分类

| 类型                   | 头字段                                                                                                                                                                              | 处理方式                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| **固定值**       | `accept`, `accept-encoding`, `content-type`, `app-key`, `bili-http-engine`, `env`, `x-bili-metadata-ip-region`, `x-bili-metadata-legal-region`, `x-bili-redirect` | 硬编码                                |
| **从配置读取**   | `buvid`, `x-bili-mid`, `fp_local`, `fp_remote`, `guestid`, `x-bili-aurora-eid`, `x-bili-locale-bin`                                                                   | 从 config.json 读                     |
| **每次动态生成** | `session_id`（8位随机hex）, `x-bili-trace-id`（随机base64）, `content-length`                                                                                                 | 运行时计算                            |
| **自动刷新**     | `x-bili-ticket`                                                                                                                                                                   | 通过 `bili_ticket.py` 自动获取/刷新 |
| **合成**         | `user-agent`                                                                                                                                                                      | 从 device 配置拼接                    |
| **HTTP/2 伪头**  | `:authority`, `:method`, `:path`, `:scheme`                                                                                                                                 | HTTP 库自动处理，不需手动设置         |

> HTTP/2 的 4 个伪头（以 `:` 开头）是协议层自动添加的，httpx 发 HTTP/1.1 时不需要管。
> 所以实际手动设置的头是 21 个左右。

---

## 五、文件结构与依赖关系

```
auto_comment/
├── config.json          # 凭据配置（gitignore，运行时 ticket 自动回写）
├── config.example.json  # 示例配置（可提交）
├── bili_ticket.py       # ticket 刷新模块
│     ├── gen_ticket()        → 调 GenWebTicket API
│     └── is_ticket_valid()   → 检查是否过期
├── bili_comment.py      # 主脚本
│     └── BiliComment 类
│           ├── ensure_ticket()    → 调 bili_ticket
│           ├── _build_params()    → 构造 24 个参数
│           ├── _build_headers()   → 构造请求头
│           └── post_comment()     → 签名 + 编码 + 发送
└── .gitignore           # 排除 config.json

sign_verify/
└── bili_sign.py         # sign 算法（被 bili_comment.py 导入）
```

---

## 六、验证阶段与排错

### Phase 1: Ticket 获取 ✅ 已通过

```bash
python bili_ticket.py
# 输出：ticket 获取成功，ttl=259200s (72h)，自动回写 config.json
```

### Phase 2: Sign 一致性 ✅ 已通过（前序工作）

在 `sign_verify/` 目录下用 3 组抓包数据验证，sign 100% 匹配。

### Phase 3: 实际发评论（待测试）

```bash
python bili_comment.py <oid> "测试评论"
```

**常见错误码**：

| code     | 含义            | 解决方案                      |
| -------- | --------------- | ----------------------------- |
| `0`    | 成功            | —                            |
| `-101` | access_key 过期 | 重新从 App 抓包获取           |
| `-111` | csrf 校验失败   | 检查参数完整性                |
| `-412` | 请求被拦截      | 检查 UA/IP/频率，可能触发风控 |
| `-509` | 请求过于频繁    | 降低频率                      |

### 排查清单

如果 Phase 3 失败：

1. **先检查 access_key** — 这是最容易过期的凭据，有效期可能只有几天
2. **对比 body 编码** — 打印签名前的 sorted_params 字符串，与抓包原文逐字对比
3. **逐步去掉 header** — 从 21 个头开始二分排查，找出哪些是必需的
4. **HTTP 版本** — 脚本用 HTTP/1.1（httpx 默认），App 用 HTTP/2，理论上服务端都支持

---

## 七、后续优化方向

- [X] **access_key 自动刷新**：目前 access_key 需要手动抓包更新，可以研究 OAuth refresh 机制
- [ ] **header 最小化**：测通后逐步去掉非必需 header，找到最小可用集合
- [ ] **批量评论**：添加随机间隔 + 评论内容变化，避免风控
- [ ] **HTTP/2 支持**：如果 HTTP/1.1 被拒，切换到 `httpx[http2]`（需安装 h2 库）

---

## 八、关键参考资料

| 资源                 | 链接                                                                                     | 说明                                     |
| -------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------- |
| bilibili-API-collect | https://github.com/SocialSisterYi/bilibili-API-collect                                   | **B站最全第三方 API 文档**，必收藏 |
| bili_ticket 文档     | https://socialsisteryi.github.io/bilibili-API-collect/docs/misc/sign/bili_ticket.html    | x-bili-ticket 获取方式                   |
| APP 签名文档         | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/misc/sign/APP.md | appkey/appsec 列表 + sign 算法           |
| bili_ticket Issue    | https://github.com/SocialSisterYi/bilibili-API-collect/issues/903                        | 社区对 ticket 机制的讨论                 |
| WBI 签名文档         | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/misc/sign/wbi.md | Web 端签名（与 APP sign 不同）           |

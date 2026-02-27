# B站 API 接口完整文档

> **日期**：2026-02-20
> **状态**：逆向完成，代码实现已验证
> **关联代码**：`auto_comment/bili_comment.py`, `auto_comment/bili_ticket.py`, `sign_verify/bili_sign.py`

---

## 目录

- [一、评论发送接口](#一评论发送接口)
  - [1.1 基础信息](#11-基础信息)
  - [1.2 请求头（21 个）](#12-请求头21-个)
  - [1.3 请求体参数（24 + sign）](#13-请求体参数24--sign)
  - [1.4 sign 签名算法](#14-sign-签名算法)
  - [1.5 请求编码关键细节](#15-请求编码关键细节)
  - [1.6 响应格式](#16-响应格式)
  - [1.7 错误码速查](#17-错误码速查)
- [二、JWT Ticket 获取接口](#二jwt-ticket-获取接口)
  - [2.1 基础信息](#21-基础信息)
  - [2.2 请求参数](#22-请求参数)
  - [2.3 hexsign 签名算法](#23-hexsign-签名算法)
  - [2.4 请求头](#24-请求头)
  - [2.5 响应格式](#25-响应格式)
  - [2.6 JWT 内部结构](#26-jwt-内部结构)
  - [2.7 有效期与刷新策略](#27-有效期与刷新策略)
  - [2.8 双端密钥对照](#28-双端密钥对照)
- [三、access_key 刷新接口](#三access_key-刷新接口)
  - [3.1 基础信息](#31-基础信息)
  - [3.2 请求体参数（12 + sign）](#32-请求体参数12--sign)
  - [3.3 签名算法](#33-签名算法)
  - [3.4 响应格式](#34-响应格式)
  - [3.5 双 token 轮转机制](#35-双-token-轮转机制)
  - [3.6 注意事项](#36-注意事项)
- [四、三个接口的依赖关系](#四三个接口的依赖关系)
- [五、配置文件结构](#五配置文件结构)
- [六、逆向来源索引](#六逆向来源索引)

---

## 一、评论发送接口

### 1.1 基础信息

| 项目 | 值 |
|------|-----|
| **URL** | `https://api.bilibili.com/x/v2/reply/add` |
| **Method** | `POST` |
| **协议** | App 实际 HTTP/2，脚本用 HTTP/1.1 亦可 |
| **Content-Type** | `application/x-www-form-urlencoded; charset=utf-8` |
| **认证方式** | body 中 `access_key` + header 中 `x-bili-ticket` |
| **防篡改** | body 中 `sign`（MD5 签名） |

### 1.2 请求头（21 个）

> 注：HTTP/2 伪头（`:authority`, `:method`, `:path`, `:scheme`）由 HTTP 库自动处理，
> App 抓包可见 27 个（含 4 个伪头 + content-length + content-type 由库自动设置），
> 脚本实际需手动构造以下 21 个。

| # | Header | 值 / 生成方式 | 类别 |
|---|--------|--------------|------|
| 1 | `accept` | `*/*` | 固定值 |
| 2 | `accept-encoding` | `gzip, deflate, br` | 固定值 |
| 3 | `app-key` | `android64` | 固定值 |
| 4 | `bili-http-engine` | `ignet` | 固定值 |
| 5 | `buvid` | 设备 BUVID（如 `XU851958B8BC...`） | 配置读取 |
| 6 | `content-length` | body 字节长度（如 `885`） | 动态计算 |
| 7 | `content-type` | `application/x-www-form-urlencoded; charset=utf-8` | 固定值 |
| 8 | `env` | `prod` | 固定值 |
| 9 | `fp_local` | 64 位 hex 指纹（如 `0fcca6e8...`） | 配置读取 |
| 10 | `fp_remote` | 同 fp_local（当前观察两者相同） | 配置读取 |
| 11 | `guestid` | 数字字符串（如 `25884827183574`） | 配置读取 |
| 12 | `session_id` | 8 位随机 hex（如 `d474c56e`） | 每次请求生成 |
| 13 | `user-agent` | 见下方格式 | 动态拼接 |
| 14 | `x-bili-aurora-eid` | Base64 编码的 EID（如 `VVcER1cHAlYO`） | 配置读取 |
| 15 | `x-bili-locale-bin` | Base64 编码的 locale protobuf | 配置读取 |
| 16 | `x-bili-metadata-ip-region` | `CN` | 固定值 |
| 17 | `x-bili-metadata-legal-region` | `CN` | 固定值 |
| 18 | `x-bili-mid` | 用户 UID（如 `435163479`） | 配置读取 |
| 19 | `x-bili-trace-id` | Base64 编码追踪标识（每次随机） | 每次请求生成 |
| 20 | `x-bili-redirect` | `1` | 固定值 |
| 21 | `x-bili-ticket` | JWT 字符串（`eyJ...`） | 动态获取/刷新 |

**User-Agent 格式**：

```
Mozilla/5.0 BiliDroid/{app_ver} (bbcallen@gmail.com) {app_ver} os/android model/{model} mobi_app/{mobi_app} build/{build} channel/{channel} innerVer/{build}10 osVer/{os_ver} network/2
```

示例：

```
Mozilla/5.0 BiliDroid/8.83.0 (bbcallen@gmail.com) 8.83.0 os/android model/MI 9 mobi_app/android build/8830500 channel/html5_search_google innerVer/8830510 osVer/13 network/2
```

**Header 分类汇总**：

| 类别 | 数量 | 说明 |
|------|------|------|
| 固定值 | 9 | 不随请求变化 |
| 配置读取 | 8 | 从 config.json 读取，设备/用户相关 |
| 每次请求动态生成 | 3 | session_id、trace_id、content-length |
| 需刷新维护 | 1 | x-bili-ticket（通过 GenWebTicket API） |

### 1.3 请求体参数（24 + sign）

| # | 参数名 | 值示例 | 来源 | 说明 |
|---|--------|--------|------|------|
| 1 | `access_key` | `9268870d42b72121...` | 配置读取 | OAuth token，过期需重新抓包 |
| 2 | `appkey` | `1d8b6e7d45233436` | 硬编码 | Android 版应用 ID |
| 3 | `build` | `8830500` | 配置读取 | App 构建号 |
| 4 | `c_locale` | `zh-Hans_CN` | 硬编码 | 客户端语言 |
| 5 | `channel` | `html5_search_google` | 配置读取 | 下载渠道 |
| 6 | `container_uuid` | `4866a0c3-c05d-4ecf-bcf9-d663452d16ce` | 每次生成 | UUID v4 |
| 7 | `disable_rcmd` | `0` | 硬编码 | 推荐开关 |
| 8 | `from_spmid` | `tm.recommend.0.0` | 硬编码 | 来源页面标识 |
| 9 | `has_vote_option` | `false` | 硬编码 | 投票选项 |
| 10 | `message` | `[笑哭]` | 参数传入 | **评论内容** |
| 11 | `mobi_app` | `android` | 配置读取 | 移动应用类型 |
| 12 | `oid` | `116083721768888` | 参数传入 | **目标视频 ID** |
| 13 | `ordering` | `heat` | 硬编码 | 排序方式 |
| 14 | `plat` | `2` | 硬编码 | 平台代码（2=Android） |
| 15 | `platform` | `android` | 配置读取 | 平台字符串 |
| 16 | `s_locale` | `zh-Hans_CN` | 硬编码 | 服务端语言 |
| 17 | `scene` | `main` | 硬编码 | 场景标识 |
| 18 | `scm_action_id` | `E89F0ACA` | 每次生成 | 8 位随机 hex（大写） |
| 19 | `spmid` | `united.player-video-detail.0.0` | 硬编码 | 源页面标识 |
| 20 | `statistics` | `{"appId":1,"platform":3,"version":"8.83.0","abtest":""}` | 动态合成 | JSON（紧凑格式） |
| 21 | `sync_to_dynamic` | `false` | 硬编码 | 同步到动态开关 |
| 22 | `track_id` | *(空字符串)* | 可选 | 追踪 ID，脚本可留空 |
| 23 | `ts` | `1771518449` | 每次生成 | Unix 秒级时间戳 |
| 24 | `type` | `1` | 参数传入 | 内容类型（1=视频评论） |
| 25 | `sign` | `75dfbb297d4634ee9d60804e170fa557` | 计算生成 | MD5 签名（见 1.4） |

**参数分类汇总**：

| 类别 | 数量 | 参数 |
|------|------|------|
| 硬编码 | 10 | appkey, c_locale, disable_rcmd, from_spmid, has_vote_option, ordering, plat, s_locale, scene, spmid, sync_to_dynamic |
| 配置读取 | 5 | access_key, build, channel, mobi_app, platform |
| 每次请求生成 | 5 | container_uuid, scm_action_id, ts, statistics, sign |
| 调用者传入 | 3 | message, oid, type |
| 可选/留空 | 1 | track_id |

**动态参数详细说明**：

以下参数虽然每次请求不同，但**不需要逆向**，可直接生成：

| 参数 | 生成方式 | 服务端是否校验 | 说明 |
|------|---------|--------------|------|
| `container_uuid` | `uuid.uuid4()` 随机生成 | 否，格式正确即可 | 容器/会话标识，随机 UUID 即可 |
| `scm_action_id` | `secrets.token_hex(4).upper()` | 否，埋点追踪用 | 8 位随机大写 hex，如 `E89F0ACA` |
| `ts` | `int(time.time())` | 是，参与 sign 校验 | 当前 Unix 秒级时间戳，不能偏差太大 |
| `statistics` | 从 config 拼接 JSON | 否，上报统计用 | 固定结构 `{"appId":1,"platform":3,"version":"8.83.0","abtest":""}` |
| `sign` | `bili_sign.py` 计算 | **是，核心防篡改** | 已逆向，见 1.4 节 |

> **结论**：这 5 个动态参数中，只有 `sign` 需要逆向算法，其余 4 个都可以自主生成。

**配置读取参数详细说明**：

| 参数 | 何时变化 | 说明 |
|------|---------|------|
| `access_key` | OAuth token 过期时 | 有效期约 180 天，过期需 refresh_token 刷新（待实现）或重新抓包 |
| `build` | **App 升级时** | 与 App 版本绑定，如 8.83.0 → `8830500`。同一版本内不变，升级后需更新 config |
| `channel` | 不变 | 下载渠道，安装后固定 |
| `mobi_app` | 不变 | 固定 `android` |
| `platform` | 不变 | 固定 `android` |

> **注意**：`build` 不是每次请求动态变化的。如果抓包看到不同的 build 值，
> 说明两次抓包之间 App 升级了。脚本中 build 需要和 User-Agent 里的 build 保持一致。

### 1.4 sign 签名算法

> **逆向来源**：`libbili.so` 中 `FUN_00109050 → FUN_0011629c → FUN_001162a8 → FUN_00118ff0`

**算法步骤**：

```
1. 取所有参数（不含 sign 本身），按 key 字母序排序
2. 对每个 value 做 URL 编码：quote(str(v), safe='')
3. 拼接为查询字符串：key1=encoded_val1&key2=encoded_val2&...
4. MD5 流式计算：
   MD5_Update(sorted_params_string)
   MD5_Update("560c52cc")    # sprintf("%08x", 0x560c52cc)
   MD5_Update("d288fed0")    # sprintf("%08x", 0xd288fed0)
   MD5_Update("45859ed1")    # sprintf("%08x", 0x45859ed1)
   MD5_Update("8bffd973")    # sprintf("%08x", 0x8bffd973)
5. MD5_Final() → 32 字符小写 hex
```

**appSecret**（4 × uint32，从 libbili.so 动态 hook 获取）：

```
[0x560c52cc, 0xd288fed0, 0x45859ed1, 0x8bffd973]
拼接字符串 = "560c52ccd288fed045859ed18bffd973"
```

**Python 实现**：

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

**编码示例**：

| 原始值 | URL 编码后 |
|--------|-----------|
| `哈哈` | `%E5%93%88%E5%93%88` |
| `[笑哭]` | `%5B%E7%AC%91%E5%93%AD%5D` |
| `{"appId":1,...}` | `%7B%22appId%22%3A1%2C...%7D` |

### 1.5 请求编码关键细节

**核心要求**：body 编码方式必须与 sign 计算时完全一致。

```python
# ✅ 正确：手工编码 body，与 sign 计算用同一个 quote() 逻辑
signed = sign_params(params)
body = "&".join(
    f"{k}={quote(str(v), safe='')}"
    for k, v in sorted(signed.items())
)
resp = client.post(url, content=body.encode("utf-8"), headers=headers)

# ❌ 错误：用 data=dict 让 httpx 自动编码（编码方式可能与 sign 不一致）
resp = client.post(url, data=signed, headers=headers)
```

### 1.6 响应格式

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
        "uname": "用户名",
        "avatar": "https://i0.hdslb.com/bfs/face/..."
      }
    }
  }
}
```

### 1.7 错误码速查

| code | 含义 | 处理方式 |
|------|------|---------|
| `0` | 成功 | — |
| `-101` | access_key 过期 | 需重新抓包获取（或实现 refresh_token 刷新） |
| `-111` | csrf 校验失败 | 检查 sign 计算是否正确 |
| `-412` | 请求被拦截（风控） | 降低频率、检查 header |
| `-509` | 频率限制 | 增大请求间隔 |

---

## 二、JWT Ticket 获取接口

### 2.1 基础信息

| 项目 | 值 |
|------|-----|
| **URL** | `https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket` |
| **Method** | `POST` |
| **协议** | App 走 gRPC（protobuf），脚本走 HTTP/1.1 兼容模式 |
| **参数位置** | URL query string（非 body） |
| **认证方式** | 无需 access_key，仅靠 HMAC 签名 |

### 2.2 请求参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `key_id` | `ec01` | 密钥 ID（Android 端） |
| `hexsign` | HMAC-SHA256 计算结果 | 64 字符 hex |
| `context[ts]` | `1771518449` | Unix 秒级时间戳 |

### 2.3 hexsign 签名算法

> **逆向来源**：`libbili.so` 中 `FUN_00109230 → FUN_001a5474 → FUN_001a6bc8`（HMAC-SHA256）
> 密钥映射：`FUN_001a6a80` 将 `"ec01"` → `"Ezlc3tgtl"`

**算法**：

```
hexsign = HMAC-SHA256(key="Ezlc3tgtl", message="ts" + timestamp_string)
```

**Python 实现**：

```python
import hmac
import hashlib
import time

ts = int(time.time())
hexsign = hmac.new(
    b"Ezlc3tgtl",            # HMAC 密钥（9 字节）
    f"ts{ts}".encode(),       # 消息 = "ts" + 时间戳字符串
    hashlib.sha256
).hexdigest()
```

**示例**：

```
ts = 1771518449
message = "ts1771518449"
key = "Ezlc3tgtl"
hexsign = "a3b7c9d1e2f3..." (64 字符 hex)
```

### 2.4 请求头

| Header | 值 | 必须 |
|--------|-----|------|
| `User-Agent` | BiliDroid UA（同评论接口） | **是**（缺失返回 412） |

> Ticket 接口的 header 要求非常简单，只需要 User-Agent。

### 2.5 响应格式

```json
{
  "code": 0,
  "data": {
    "ticket": "eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9...",
    "created_at": 1771519929,
    "ttl": 259200
  }
}
```

| 字段 | 说明 |
|------|------|
| `ticket` | JWT 字符串，用作请求头 `x-bili-ticket` |
| `created_at` | 签发时间（Unix 秒） |
| `ttl` | 声明有效期 = 259200 秒（3 天） |

### 2.6 JWT 内部结构

**Header**（Base64 解码）：

```json
{
  "alg": "HS256",
  "kid": "s03",
  "typ": "JWT"
}
```

**Payload**（Base64 解码）：

```json
{
  "exp": 1771548129,
  "iat": 1771519929,
  "buvid": "XU851958B8BC3412258E291F5D3152432F1CA"
}
```

| 字段 | 说明 |
|------|------|
| `exp` | 过期时间（Unix 秒） |
| `iat` | 签发时间（Unix 秒） |
| `buvid` | 设备 BUVID |
| `exp - iat` | ≈ 28200 秒 ≈ **8 小时**（JWT 真实有效期） |

**逆向技巧：JWT 的 `eyJ` 特征**

JWT 格式为 `Base64(Header).Base64(Payload).Base64(Signature)`，而 Header 几乎都以 `{"` 开头：

```
字符  { "    → 字节  0x7B 0x22  → Base64 编码  "eyJ"
```

因此**几乎所有 JWT 都以 `eyJ` 开头**。在逆向中可以用这个特征快速过滤，比如 hook SharedPreferences 时过滤 `value.startsWith("eyJ")` 就能精准捕获所有 JWT 读写。

### 2.7 有效期与刷新策略

| 指标 | 值 | 来源 |
|------|-----|------|
| 接口声明 ttl | 259200 秒（3 天） | 响应 `data.ttl` |
| JWT 实际有效期 | ~28200 秒（~8 小时） | JWT payload `exp - iat` |
| 脚本刷新策略 | 提前 300 秒（5 分钟）刷新 | `is_ticket_valid(margin=300)` |

> 脚本以 `created_at + ttl` 为基准判断过期，提前 5 分钟触发刷新。
> 实际上 JWT 的 `exp` 比 `created_at + ttl` 更短，用 ttl 判断是保守策略。

### 2.8 双端密钥对照

| 端 | key_id | HMAC Key | 来源 |
|----|--------|----------|------|
| **Android** | `ec01` | `Ezlc3tgtl` | libbili.so 逆向（FUN_001a6a80 密钥映射） |
| **Web** | `ec02` | `XgwSnGZ1p` | 开源文档 |

> 两端使用不同密钥，但算法相同：`HMAC-SHA256(key, "ts" + timestamp)`

---

## 三、access_key 刷新接口

### 3.1 基础信息

| 项目 | 值 |
|------|-----|
| **URL** | `https://passport.bilibili.com/x/passport-login/oauth2/refresh_token` |
| **Method** | `POST` |
| **Content-Type** | `application/x-www-form-urlencoded` |
| **认证方式** | body 中 `access_key` + `refresh_token` |
| **防篡改** | body 中 `sign`（MD5 签名，与评论接口完全一致） |

> **注意**：接口路径是 `/x/passport-login/oauth2/refresh_token`（V2 版），
> 开源文档中的 `/api/v2/oauth2/refresh_token` 是旧版，以逆向结果为准。

### 3.2 请求体参数（12 + sign）

| # | 参数名 | 值 | 来源 | 说明 |
|---|--------|-----|------|------|
| 1 | `access_key` | 当前的 access_key | 配置读取 | 即使过期也要传 |
| 2 | `appkey` | `1d8b6e7d45233436` | 硬编码 | 与评论接口相同 |
| 3 | `build` | `8830500` | 配置读取 | App 构建号 |
| 4 | `buvid` | 设备 BUVID | 配置读取 | 设备标识 |
| 5 | `c_locale` | `zh-Hans_CN` | 硬编码 | 客户端语言 |
| 6 | `channel` | `html5_search_google` | 配置读取 | 下载渠道 |
| 7 | `local_id` | 同 buvid | 配置读取 | 本地 ID |
| 8 | `mobi_app` | `android` | 硬编码 | 移动应用类型 |
| 9 | `platform` | `android` | 硬编码 | 平台 |
| 10 | `refresh_token` | 当前的 refresh_token | 配置读取 | 刷新令牌 |
| 11 | `s_locale` | `zh-Hans_CN` | 硬编码 | 服务端语言 |
| 12 | `sts` | `1771528555` | 每次生成 | Unix 秒级时间戳（同 ts） |
| 13 | `sign` | MD5 签名 | 计算生成 | 与评论接口完全相同的算法 |

**参数对比**：相比评论接口（24 个参数），刷新接口简单得多——核心就是 `access_key` + `refresh_token` + `sts` + 公共参数 + `sign`。

> **`sts` 参数**：jadx 中参数名为 `sts`（server timestamp），
> 实际传入的就是当前 Unix 秒级时间戳，和评论接口的 `ts` 参数含义完全一致。
> 通过 Frida hook `BiliPassportApi.U()` 方法动态确认。

### 3.3 签名算法

**与评论接口完全一致**，直接复用 `bili_sign.py`：

```python
from bili_sign import sign_params

params = {
    "access_key": "当前access_key",
    "appkey": "1d8b6e7d45233436",
    "build": "8830500",
    "buvid": "XU851958B8BC...",
    "c_locale": "zh-Hans_CN",
    "channel": "html5_search_google",
    "local_id": "XU851958B8BC...",
    "mobi_app": "android",
    "platform": "android",
    "refresh_token": "当前refresh_token",
    "s_locale": "zh-Hans_CN",
    "sts": str(int(time.time())),
}
signed = sign_params(params)  # 自动加入 sign 字段
```

> **逆向确认**：jadx 中 `AuthInterceptor.signQuery()` 调用的是 `LibBili.signQuery()`，
> 和评论接口走的是同一个 SO 层签名函数。

### 3.4 响应格式

**成功响应**（`code = 0`）：

```json
{
  "code": 0,
  "data": {
    "token_info": {
      "mid": 435163479,
      "access_token": "新的 access_key",
      "refresh_token": "新的 refresh_token",
      "expires_in": 15552000
    },
    "cookie_info": { ... }
  }
}
```

| 字段 | 说明 |
|------|------|
| `access_token` | 新的 access_key（旧的失效） |
| `refresh_token` | 新的 refresh_token（旧的失效） |
| `expires_in` | 有效期 = 15552000 秒（180 天） |
| `mid` | 用户 UID |
| `cookie_info` | Web 端 cookie（App 端可忽略） |

### 3.5 双 token 轮转机制

```
刷新前：
  access_key  = AAAA（有效 / 过期）
  refresh_token = XXXX（有效）

调用 refresh_token 接口：
  POST → 传入 AAAA + XXXX

刷新后：
  access_key  = BBBB（新的，有效 180 天）  ← 旧的 AAAA 失效
  refresh_token = YYYY（新的）              ← 旧的 XXXX 失效
```

**关键**：每次刷新后，新旧 token **全部轮转**，必须保存新的 refresh_token，否则无法再次刷新。

### 3.6 注意事项

| 注意 | 说明 |
|------|------|
| 必须保存新 refresh_token | 刷新后旧 token 失效，不保存 = 只能重新登录 |
| access_key 过期也能刷新 | 只要 refresh_token 有效就行 |
| refresh_token 有效期未知 | 比 access_key 长，但具体时间未明确 |
| 不要频繁刷新 | 每次刷新都产生新 token 对，频繁调用可能触发风控 |
| 建议提前刷新 | 在 access_key 过期前 1-7 天刷新，避免服务中断 |

---

## 四、三个接口的依赖关系

```
┌────────────────────────────┐
│   refresh_token API        │  ← 用 refresh_token 换新 access_key
│   刷新 access_key          │
└──────────┬─────────────────┘
           │ 新 access_key + 新 refresh_token
           ▼
┌────────────────────────────┐
│   GenWebTicket API         │  ← 无认证依赖，仅需 HMAC 签名
│   获取 x-bili-ticket       │
└──────────┬─────────────────┘
           │ ticket (JWT)
           ▼
┌────────────────────────────┐
│   /x/v2/reply/add API      │  ← 需要 ticket + access_key + sign
│   发送评论                  │
└────────────────────────────┘
```

**完整调用流程**：

```
1. 检查 access_key 是否过期
   ├─ 未过期 → 继续
   └─ 已过期 → 调 refresh_token 接口换新 → 保存新 token 到 config.json
2. 检查本地缓存的 ticket 是否过期
   ├─ 未过期 → 直接使用
   └─ 已过期 → 调 GenWebTicket 获取新 ticket → 保存到 config.json
3. 构造评论请求的 24 个参数
4. 计算 sign（MD5 + appSecret）
5. 拼接 body（URL 编码，与 sign 计算方式一致）
6. 构造 headers（含 x-bili-ticket）
7. POST → 解析响应
```

---

## 五、配置文件结构

`config.json`（`config.example.json` 为模板）：

```json
{
    "access_key": "OAuth access_token（从抓包获取）",
    "buvid": "设备 BUVID",
    "mid": "用户 UID",

    "device": {
        "build": "8830500",
        "channel": "html5_search_google",
        "mobi_app": "android",
        "platform": "android",
        "model": "MI 9",
        "os_ver": "13",
        "app_ver": "8.83.0"
    },

    "fingerprint": {
        "fp_local": "64 位 hex 指纹",
        "fp_remote": "64 位 hex 指纹",
        "guestid": "数字字符串",
        "aurora_eid": "Base64 EID",
        "locale_bin": "Cg4KAnpoEgRIYW5zGgJDThII..."
    },

    "ticket": {
        "value": "eyJ...（运行时自动填充）",
        "created_at": 0,
        "ttl": 0
    }
}
```

**凭据获取方式**：

| 凭据 | 获取方式 | 过期处理 |
|------|---------|---------|
| `access_key` | Frida 抓包评论请求 body | ✅ refresh_token 自动刷新（已实现） |
| `refresh_token` | Frida `Java.choose` 读取内存实例 | 每次刷新后更新，需持久化保存 |
| `buvid` | 抓包请求头 | ❌ 不过期，抓包一次永久使用 |
| `mid` | 抓包请求头 `x-bili-mid` | 用户 UID，不变 |
| `fp_local` / `fp_remote` | 抓包请求头 | 设备指纹，基本不变 |
| `guestid` / `aurora_eid` | 抓包请求头 | 基本不变 |
| `ticket` | 脚本自动刷新 | ✅ 全自动 |

**凭据生命周期总结**：

| 凭据 | 过期时间 | 自动续期 | 需要逆向生成算法？ |
|------|---------|---------|------------------|
| `ticket` | ~3 天 | ✅ 已实现 | ❌ 接口调用即可 |
| `access_key` | 180 天 | ✅ 已实现 | ❌ refresh_token 刷新 |
| `refresh_token` | 未知（>180天） | ✅ 随 access_key 一起轮转 | ❌ 跟随刷新 |
| `buvid` | **不过期** | 不需要 | ❌ 设备安装时生成，绑定设备，永久有效 |
| `fp_local` / `fp_remote` | **不过期** | 不需要 | ❌ 设备指纹，基本不变 |
| `guestid` / `aurora_eid` | **不过期** | 不需要 | ❌ 基本不变 |

> **buvid 说明**：buvid 是设备级别的唯一标识，App 安装时生成，绑定设备硬件信息，
> 不会过期也不会变化。抓包获取一次即可永久使用。
> 除非需要多设备/多账号场景（不抓包就能生成新 buvid），否则不需要逆向其生成算法。
> 当前优先级：低。

---

## 六、逆向来源索引

| 内容 | 逆向方式 | 详细记录 |
|------|---------|---------|
| 请求头 27 个字段 | Frida 抓包 mitmproxy | `bilibili_评论接口完整逆向记录.md` |
| 请求体 24 个参数 | Frida 抓包 mitmproxy | `bilibili_评论接口完整逆向记录.md` |
| sign 算法（MD5 + appSecret） | Frida + Ghidra 动静结合 | `sign逆向分析实录.md`、`bilibili_sign动态逆向完整实战.md` |
| appSecret 4 × uint32 | Frida hook sprintf | `bilibili_sign动态逆向完整实战.md` |
| GenWebTicket 接口 | jadx 静态分析 Java 层 | `bilibili_ticket逆向实战记录.md` 第 1-8 章 |
| HMAC-SHA256 签名 | Frida + Ghidra SO 层逆向 | `bilibili_ticket逆向实战记录.md` 第 9-15 章 |
| ec01 → Ezlc3tgtl 密钥映射 | Frida native hook | `bilibili_ticket逆向实战记录.md` 第 11 章 |
| JWT 结构 | Base64 解码分析 | `bilibili_自动评论脚本技术沉淀.md` |
| access_key 刷新接口 | Frida + jadx Retrofit 注解 | `bilibili_access_key刷新逆向实战记录.md` |
| refresh_token 获取 | Frida `Java.choose` 内存实例 | `bilibili_access_key刷新逆向实战记录.md` 第三章 |
| AuthInterceptor 公共参数 | jadx 静态分析 | `bilibili_access_key刷新逆向实战记录.md` 第四章 |

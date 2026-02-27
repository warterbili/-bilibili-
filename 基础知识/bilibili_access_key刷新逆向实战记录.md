# B站 access_key 刷新逆向实战记录

> **日期**：2026-02-20
> **前置知识**：
> - [bilibili_ticket逆向实战记录.md](./bilibili_ticket逆向实战记录.md) — ticket 逆向方法论（本次复用）
> - [bilibili_API接口完整文档.md](./bilibili_API接口完整文档.md) — 完整 API 汇总
> - [bilibili_token刷新机制调研.md](./bilibili_token刷新机制调研.md) — 开源文档调研
>
> **目标**：逆向 App 中 access_key 的自动刷新机制，实现 Python 自动续期
> **产出**：完整的刷新接口文档 + 逆向方法论沉淀

---

## 一、问题背景

自动评论脚本依赖两个会过期的凭据：

| 凭据 | 状态 | 问题 |
|------|------|------|
| **x-bili-ticket**（JWT） | ✅ 已实现自动刷新 | `bili_ticket.py` 调 GenWebTicket 接口 |
| **access_key**（OAuth Token） | ❌ 过期只能重新抓包 | 有效期 180 天，过期后脚本完全不可用 |

**核心问题**：access_key 过期后怎么办？App 不可能每次都让用户重新登录，一定有自动刷新机制。

---

## 二、逆向思路分析

### 2.1 我们已有的能力

从之前 sign 和 ticket 的逆向中，我们积累了：

| 能力 | 来源 |
|------|------|
| sign 签名算法（MD5 + appSecret） | `bili_sign.py`，已验证 |
| Frida bypass 反检测 | `bypass.js` |
| SP hook、类名搜索、方法枚举 | ticket 逆向经验 |
| SO 层逆向（Ghidra + Frida） | sign / ticket 实战 |

### 2.2 关键判断：需要逆向什么？

刷新接口的 sign 算法**和评论接口完全一致**（后来验证确实如此），所以：
- ❌ 不需要逆向新的签名算法
- ✅ 需要找到：刷新接口地址、参数列表、refresh_token 值

### 2.3 方法论选择

按照 ticket 逆向建立的方法论：**先 Frida 动态发现 → 再 jadx 静态分析**。

```
Step 1: Frida 搜索类名 → 找到 token 管理的入口类
Step 2: 枚举方法/字段 → 了解数据结构
Step 3: 读取内存实例 → 拿到实际的 token 值
Step 4: jadx 静态分析 → 找到接口定义和参数
Step 5: Frida 动态验证 → 主动触发刷新，确认完整流程
```

> **与 ticket 逆向的对比**：ticket 逆向时，SP hook 失败（B站不用 SP 存 ticket），
> 被迫换思路搜类名。这次我们直接从类名搜索开始，跳过了 SP 这一步。
> 这是方法论的进化——从失败中学到的经验直接复用。

---

## 三、Frida 动态探索过程

### 3.1 搜索 token 相关类名

**脚本**：`trace_access_token.js`

```javascript
Java.enumerateLoadedClasses({
    onMatch: function(name) {
        var lower = name.toLowerCase();
        if ((lower.indexOf("refreshtoken") !== -1
            || lower.indexOf("accesstoken") !== -1
            || lower.indexOf("biliauth") !== -1)
            && lower.indexOf("facebook") === -1
            && lower.indexOf("sina") === -1) {
            console.log("[class] " + name);
        }
    },
    onComplete: function() {}
});
```

> **关键词选择**：搜 `refreshtoken`、`accesstoken`、`biliauth`，
> 同时排除第三方 SDK（facebook、sina）的干扰类。

**结果**：

```
[class] com.bilibili.lib.accounts.model.AccessToken    ← 数据模型
[class] com.bilibili.lib.accounts.service.AccessToken   ← 服务接口
```

**分析**：找到两个 `AccessToken` 类——一个是 model（存数据），一个是 service（定义操作）。
先看 model，因为数据模型能告诉我们"有哪些字段"。

### 3.2 枚举 AccessToken 模型的字段和方法

```javascript
var model = Java.use("com.bilibili.lib.accounts.model.AccessToken");
model.class.getDeclaredFields().forEach(function(f) { console.log("  " + f); });
model.class.getDeclaredMethods().forEach(function(m) { console.log("  " + m); });
```

**结果**：

```
字段：
  mAccessKey        ← access_key 值
  mRefreshToken     ← refresh_token 值！
  mExpires          ← 过期时间
  mExpiresIn        ← 有效期
  mMid              ← 用户 UID
  mFastLoginToken   ← 快速登录 token

方法：
  canRefresh()      ← 判断能否刷新
  isExpired()       ← 判断是否过期
  isValid()         ← 判断是否有效
  getAccessKey()    ← 读取 access_key
  getMid()          ← 读取 UID
```

**发现**：模型中直接就有 `mRefreshToken` 字段！说明 refresh_token 和 access_key 存储在同一个对象中。

### 3.3 从内存中读取实际 token 值

```javascript
Java.choose("com.bilibili.lib.accounts.model.AccessToken", {
    onMatch: function(instance) {
        console.log("│ mAccessKey     = " + instance.mAccessKey.value);
        console.log("│ mRefreshToken  = " + instance.mRefreshToken.value);
        console.log("│ mMid           = " + instance.mMid.value);
        console.log("│ mExpires       = " + instance.mExpires.value);
        console.log("│ mExpiresIn     = " + instance.mExpiresIn.value);
        console.log("│ canRefresh()   = " + instance.canRefresh());
        console.log("│ isExpired()    = " + instance.isExpired());
    },
    onComplete: function() {}
});
```

**结果**（3 个实例）：

| 实例 | mAccessKey | mRefreshToken | mMid | mExpires | 状态 |
|------|-----------|---------------|------|---------|------|
| #1 | `NO_LOGIN_TOKEN_STRING_` | null | -10000 | 0 | 未登录默认值 |
| #2 | `9268870d42b72121...` | `811ee6ead35ca06bbdc8db147f341f21` | 435163479 | 1786976895 | ✅ 当前登录 |
| #3 | 同上 | 同上 | 同上 | 同上 | 同上的副本 |

**关键收获**：
- **refresh_token = `811ee6ead35ca06bbdc8db147f341f21`**（32 字符 hex，和 MD5 hash 格式一致）
- expires = 1786976895（约 2026-08-17），有效期 180 天
- canRefresh() = true，说明当前可以执行刷新

> **心路历程**：之前尝试用 `adb shell su -c "grep -ri 'refresh' /data/data/tv.danmaku.bili/shared_prefs/"`
> 在设备 SP 文件中搜索 refresh_token，结果为空。说明 B站不把 token 存在 SP 里
>（和 ticket 的情况一样）。但通过 `Java.choose` 直接搜索内存中的对象实例，
> 一步到位拿到了所有 token 信息。这再次验证了：**从使用方（内存对象）入手比从存储方（SP/文件）入手更可靠**。

### 3.4 扩大搜索：找到 accounts 包完整体系

为了找到刷新逻辑的入口，搜索整个 `com.bilibili.lib.accounts` 包：

```javascript
Java.enumerateLoadedClasses({
    onMatch: function(name) {
        if (name.indexOf("com.bilibili.lib.accounts") !== -1
            && name.indexOf("$") === -1
            && name.indexOf("lambda") === -1) {
            console.log("[class] " + name);
        }
    },
    onComplete: function() {}
});
```

**关键类**：

| 类 | 角色 |
|---|------|
| `BiliAccounts` | 主管理类（入口） |
| `BiliAuthService` | Retrofit 接口定义（网络层） |
| `BiliPassportApi` | API 工厂，创建 BiliAuthService 实例 |
| `AuthInterceptor` | OkHttp 拦截器，注入公共参数和签名 |
| `AccountStorage` | token 持久化存储 |
| `AuthInfo` | 刷新接口的返回值模型 |

### 3.5 枚举 BiliAccounts 方法

```javascript
var cls = Java.use("com.bilibili.lib.accounts.BiliAccounts");
cls.class.getDeclaredMethods().forEach(function(m) { console.log("  " + m); });
```

**与刷新相关的方法**：

| 方法 | 作用 |
|------|------|
| `loadAccessToken()` | 读取当前 token |
| `isTokenExpired()` | 检查过期 |
| `isTokenValid()` | 检查有效性 |
| `getAccessKey()` | 获取 access_key 字符串 |
| `signedInWithToken(AuthInfo)` | 刷新成功后保存新 token |
| `requestForAuthInfo(String, String)` | 请求认证信息 |
| `requestForAuthInfoV2(String, String)` | V2 版本 |

> 没有直接叫 "refreshToken" 的方法，说明刷新逻辑在更底层（BiliAuthService）。

### 3.6 枚举 BiliAuthService 方法

```javascript
var svc = Java.use("com.bilibili.lib.accounts.BiliAuthService");
svc.class.getDeclaredMethods().forEach(function(m) { console.log("  " + m); });
```

**发现 `refreshTokenV2`**：

```
public abstract BiliCall refreshTokenV2(String, String, String, Map)
```

所有方法都是 `abstract`——这是 **Retrofit 接口**，接口地址和参数名在注解中。
需要去 jadx 查看注解。

---

## 四、jadx 静态分析

### 4.1 BiliAuthService 接口定义

在 jadx 中打开 `com.bilibili.lib.accounts.BiliAuthService`，找到 `refreshTokenV2`：

```java
@BaseUrl("https://passport.bilibili.com")
public interface BiliAuthService {

    @FormUrlEncoded
    @POST("/x/passport-login/oauth2/refresh_token")
    @RequestInterceptor(AuthInterceptor.class)
    BiliCall<GeneralResponse<AuthInfo>> refreshTokenV2(
        @Field("access_key")    String str,
        @Field("refresh_token") String str2,
        @Field("sts")           String str3,
        @FieldMap               Map<String, String> map
    );
}
```

**关键发现**：

| 项目 | 值 |
|------|-----|
| 基地址 | `https://passport.bilibili.com` |
| 接口路径 | `/x/passport-login/oauth2/refresh_token` |
| 方法 | `POST`，`FormUrlEncoded` |
| 参数 1 | `access_key` — 当前的 access_token |
| 参数 2 | `refresh_token` — 刷新令牌 |
| 参数 3 | `sts` — 待确认（疑似时间戳） |
| 参数 4 | `FieldMap` — 公共参数（由 AuthInterceptor 注入） |
| 拦截器 | `AuthInterceptor.class` — 添加公共参数 + 签名 |
| 返回值 | `AuthInfo` — 包含新的 token 信息 |

> **注意**：接口路径是 `/x/passport-login/oauth2/refresh_token`（V2 版），
> 不是开源文档中的 `/api/v2/oauth2/refresh_token`（旧版）。
> 这说明 B站已经升级了接口，开源文档可能过时。

### 4.2 找到调用方

在 jadx 中用**代码**搜索 `refreshTokenV2`，找到调用方：

```java
// com.bilibili.lib.accounts.BiliPassportApi
@JvmStatic
public static final AuthInfo U(String str, String str2, String str3)
        throws AccountException {
    BiliPassportApi biliPassportApi = f144933a;
    return biliPassportApi.u(
        biliPassportApi.E().refreshTokenV2(str, str2, str3,
            PassportCommParams.createDeviceParams())
    );
}
```

调用链：`BiliPassportApi.U()` → `BiliAuthService.refreshTokenV2()`

参数映射：
- `str` → `access_key`
- `str2` → `refresh_token`
- `str3` → `sts`（仍需确认含义）
- 第四个 → `PassportCommParams.createDeviceParams()` 自动注入

### 4.3 AuthInterceptor 公共参数分析

在 jadx 中查看 `AuthInterceptor.addCommonParam`：

```java
protected void addCommonParam(Map<String, String> map) {
    map.put("platform", "android");
    map.put("mobi_app", AccountConfig.paramDelegate.getMobiApp());
    map.put("appkey", getAppKey());
    map.put("build", AccountConfig.paramDelegate.getAppVersionCode());
    map.put("buvid", AccountConfig.paramDelegate.getBuvid());
    map.put("local_id", AccountConfig.paramDelegate.getBuvid());
    map.put("channel", AccountConfig.paramDelegate.getChannel());
    map.put("c_locale", AccountConfig.paramDelegate.getCurrentLocale());
    map.put("s_locale", AccountConfig.paramDelegate.getSystemLocale());
}
```

**公共参数列表**：

| 参数 | 值 |
|------|-----|
| `platform` | `"android"` |
| `mobi_app` | `"android"` |
| `appkey` | `"1d8b6e7d45233436"` |
| `build` | `"8830500"` |
| `buvid` | 设备 BUVID |
| `local_id` | 同 buvid |
| `channel` | `"html5_search_google"` |
| `c_locale` | `"zh-Hans_CN"` |
| `s_locale` | `"zh-Hans_CN"` |

### 4.4 签名方式确认

`AuthInterceptor.signQuery` 中：

```java
protected SignedQuery signQuery(Map<String, String> map) {
    return LibBili.signQuery(map, ...);
}
```

**确认**：签名调用的是 `LibBili.signQuery`，和评论接口完全一致，直接复用 `bili_sign.py`。

---

## 五、Frida 动态验证

### 5.1 Hook refreshTokenV2 调用

```javascript
Java.perform(function() {
    var cls = Java.use("com.bilibili.lib.accounts.BiliPassportApi");
    cls.U.implementation = function(str, str2, str3) {
        console.log("┌─── refreshTokenV2 调用 ───");
        console.log("│ access_key    = " + str);
        console.log("│ refresh_token = " + str2);
        console.log("│ sts           = " + str3);
        console.log("└────────────────────────────");
        return this.U(str, str2, str3);
    };
});
```

### 5.2 主动触发刷新

由于 access_key 有效期 180 天，不会自然触发刷新，需要主动调用：

```javascript
Java.perform(function() {
    var cls = Java.use("com.bilibili.lib.accounts.BiliPassportApi");
    var result = cls.U(
        "当前access_key",
        "当前refresh_token",
        "" + Math.floor(Date.now()/1000)
    );
});
```

**Hook 输出**：

```
┌─── refreshTokenV2 调用 ───
│ access_key    = 9268870d42b72121...
│ refresh_token = 811ee6ead35ca06bbdc8db147f341f21
│ sts           = 1771528555
└────────────────────────────
```

**`sts` 确认**：就是 **Unix 秒级时间戳**（和 `ts` 一样的含义）。

### 5.3 验证刷新结果

刷新成功后，再次读取内存中的 AccessToken 实例：

```javascript
Java.choose("com.bilibili.lib.accounts.model.AccessToken", {
    onMatch: function(instance) {
        console.log("│ mAccessKey     = " + instance.mAccessKey.value);
        console.log("│ mRefreshToken  = " + instance.mRefreshToken.value);
        console.log("│ mExpires       = " + instance.mExpires.value);
    },
    onComplete: function() {}
});
```

**新旧 token 对比**：

| | 刷新前 | 刷新后 |
|---|--------|--------|
| **access_key** | `9268870d42b72121...` | `8b5cb21c63603638...` |
| **refresh_token** | `811ee6ead35ca06b...` | `63ea829f3eca522b...` |
| **expires** | `1786976895` | `1787080605`（+约 1 天） |

**关键发现**：
1. 刷新后 access_key 和 refresh_token **都换新了**（标准 OAuth2 双 token 轮转）
2. 新 token 的过期时间从当前时间算起 +180 天
3. 旧的 refresh_token 刷新后**失效**，不能重复使用
4. 返回的 `AuthInfo` 包含 `status = 0` 表示成功

---

## 六、完整接口还原

### 6.1 请求

```
POST https://passport.bilibili.com/x/passport-login/oauth2/refresh_token
Content-Type: application/x-www-form-urlencoded

参数（按字母序，含 sign）：
  access_key    = 当前 access_key
  appkey        = 1d8b6e7d45233436
  build         = 8830500
  buvid         = 设备 BUVID
  c_locale      = zh-Hans_CN
  channel       = html5_search_google
  local_id      = 同 buvid
  mobi_app      = android
  platform      = android
  refresh_token = 当前 refresh_token
  s_locale      = zh-Hans_CN
  sts           = Unix 秒级时间戳
  sign          = MD5 签名（bili_sign.py 计算）
```

### 6.2 响应

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

### 6.3 注意事项

| 注意 | 说明 |
|------|------|
| 双 token 轮转 | 刷新后旧的 access_key 和 refresh_token 都失效 |
| 必须保存新 refresh_token | 否则下次无法刷新，只能重新登录 |
| sign 复用 | 和评论接口完全相同的 MD5 + appSecret 算法 |
| sts 就是时间戳 | 和其他接口的 `ts` 参数含义一致 |

---

## 七、踩坑记录

| # | 问题 | 原因 | 解决 |
|---|------|------|------|
| 1 | SP 文件搜不到 refresh_token | B站不用 SP 存 token | 用 `Java.choose` 搜索内存对象 |
| 2 | `Java.choose` 用 `===` 比较 mMid 无结果 | mMid 是 Java `long` 类型，JS `===` 比较不匹配 | 去掉过滤条件，打印所有实例 |
| 3 | jadx 搜 `.U(` 太通用 | 混淆后的方法名太短 | 搜 `refreshTokenV2` 找调用方 |
| 4 | 开源文档的接口地址是旧版 | App 已升级到 V2 接口 | 以 jadx 逆向结果为准 |
| 5 | 刷新后 Frida REPL 中 `api` 变量丢失 | REPL 每次 `Java.perform` 是独立作用域 | 在同一个 `Java.perform` 块中完成所有操作 |

---

## 八、方法论总结

### 8.1 本次逆向路径

```
Frida 搜索类名（"accesstoken" / "biliauth"）
  ↓
找到 AccessToken 模型类 → 枚举字段（发现 mRefreshToken）
  ↓
Java.choose 读取内存实例 → 拿到 refresh_token 值
  ↓
扩大搜索 com.bilibili.lib.accounts 包 → 找到 BiliAuthService
  ↓
jadx 查看 Retrofit 注解 → 拿到接口地址 + 参数名
  ↓
jadx 查看 AuthInterceptor → 确认公共参数 + 签名方式
  ↓
Frida hook BiliPassportApi.U → 确认 sts = 时间戳
  ↓
主动触发刷新 → 验证新旧 token 轮转
```

### 8.2 与 ticket 逆向的对比

| 环节 | ticket 逆向 | access_key 刷新 |
|------|------------|----------------|
| 起点 | SP hook（失败）→ 类名搜索 | 直接类名搜索（复用经验） |
| 数据获取 | hook onTicketReq 拿 JWT | Java.choose 读内存实例 |
| 接口发现 | jadx 追踪 Java 调用链 | jadx 查看 Retrofit 注解 |
| 签名算法 | 需要逆向 SO 层 HMAC-SHA256 | 直接复用已有的 sign 算法 |
| 动态验证 | 手动调用 LibBili.st() | 手动调用 BiliPassportApi.U() |

### 8.3 核心经验

1. **方法论复用**：ticket 逆向中建立的"先动态后静态"方法论，在 access_key 刷新中完美复用
2. **从失败中学习**：SP 搜索失败的经验让我们直接跳过 SP，从内存对象入手
3. **SO 层突破的复利**：sign 算法逆向一次，所有接口复用，刷新接口不需要额外逆向
4. **Retrofit 注解是宝藏**：对于使用 Retrofit 的 App，接口定义全在注解里，jadx 一目了然

---

## 九、产出文件

| 文件 | 用途 |
|------|------|
| `bilibili_frida绕过/trace_access_token.js` | Frida 脚本，搜索 token 相关类名 |
| `基础知识/bilibili_access_key刷新逆向实战记录.md` | 本文档，完整逆向过程记录 |
| `基础知识/bilibili_API接口完整文档.md` | 更新，新增刷新接口章节 |

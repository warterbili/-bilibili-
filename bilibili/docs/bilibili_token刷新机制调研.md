# B站 Token 刷新机制调研

> **前置文档**：
> - [bilibili_自动评论脚本技术沉淀.md](./bilibili_自动评论脚本技术沉淀.md) — JWT ticket 获取 + 完整知识体系
> - [bilibili_评论接口完整逆向记录.md](./bilibili_评论接口完整逆向记录.md) — 请求头/请求体/sign
>
> **日期**：2026-02-20
> **状态**：开源文档调研完成，逆向实现待做

---

## 一、问题背景

自动评论脚本依赖两个会过期的凭据：

| 凭据 | 当前状态 | 问题 |
|------|---------|------|
| **x-bili-ticket**（JWT） | ✅ 已实现自动刷新 | `bili_ticket.py` 调 GenWebTicket 接口 |
| **access_key**（OAuth Token） | ❌ 过期只能重新抓包 | 需要 refresh_token 才能自动续期 |

要让脚本长期运行不需要人工干预，必须解决 access_key 的自动刷新。

---

## 二、B站的双 Token 体系

### 2.1 登录时服务端返回什么

用户登录（扫码/短信/密码）成功后，服务端返回两个 token：

```json
{
  "token_info": {
    "mid": 435163479,
    "access_token": "9268870d42b7...",
    "refresh_token": "xxxxxxxxxxxx...",
    "expires_in": 15552000
  }
}
```

| 字段 | 说明 |
|------|------|
| `access_token` | 就是我们说的 access_key，API 认证用 |
| `refresh_token` | 用于换取新 access_token 的凭据 |
| `expires_in` | access_token 有效期，单位秒 |

### 2.2 两个 token 的关系

```
access_token（短命）           refresh_token（长命）
  ├─ 用于每次 API 请求           ├─ 只用于刷新 access_token
  ├─ 有效期 ~180 天              ├─ 有效期比 access_token 更长（未明确）
  └─ 过期后 API 返回 -101        └─ 过期后必须重新登录
```

这是标准的 **OAuth2 双 Token 模式**：

```
登录 → 拿到 access_token + refresh_token
        │
        ├─ 正常使用：每次请求带 access_token
        │
        ├─ access_token 过期 → 用 refresh_token 换新的
        │   └─ 返回新的 access_token + 新的 refresh_token
        │
        └─ refresh_token 也过期 → 必须重新登录（扫码/短信/密码）
```

### 2.3 为什么要两个 token？一个不行吗？

```
如果只有 access_token：
  ├─ 有效期设很长（1年）→ 泄露了风险大，攻击者能用很久
  └─ 有效期设很短（1天）→ 用户天天要重新登录，体验差

双 token 方案：
  ├─ access_token 短命 → 泄露了影响有限
  ├─ refresh_token 长命 → 但只能换 token，不能直接调 API
  └─ 刷新时同时换掉两个 → 旧的 refresh_token 也失效，降低风险
```

---

## 三、access_key 刷新接口

### 3.1 接口详情（来自开源文档）

**端点**：

```
POST https://passport.bilibili.com/api/v2/oauth2/refresh_token
```

**请求参数**：

| 参数 | 值 | 说明 |
|------|-----|------|
| `access_key` | 当前的 access_token | 即使过期也要传 |
| `appkey` | `1d8b6e7d45233436` | 和发评论用同一个 |
| `refresh_token` | 登录时获得的 | **我们目前没有，需要抓包获取** |
| `ts` | Unix 时间戳 | 秒级 |
| `sign` | MD5 签名 | 和 `bili_sign.py` 完全一致的算法 |

**Content-Type**：`application/x-www-form-urlencoded`

**响应**（成功时 code=0）：

```json
{
  "code": 0,
  "data": {
    "token_info": {
      "mid": 435163479,
      "access_token": "新的 access_token...",
      "refresh_token": "新的 refresh_token...",
      "expires_in": 15552000
    },
    "cookie_info": { ... }
  }
}
```

> **关键发现**：sign 算法和我们已还原的 `bili_sign.py` 完全一致，
> 不需要额外逆向签名逻辑，直接复用即可。

### 3.2 有效期

| Token | 有效期 | 来源 |
|-------|--------|------|
| access_token | `expires_in = 15552000` 秒 ≈ **180 天** | 开源文档 + 代码实现 |
| refresh_token | 未明确，比 access_token 长 | 开源文档未记录具体值 |

---

## 四、当前缺失：refresh_token

我们之前的抓包只关注了评论接口，**没有抓到登录流程**，所以没有 refresh_token。

### 获取 refresh_token 的方案

**方案 A：Hook SharedPreferences 搜索**

App 一定会把 refresh_token 缓存在本地。直接读：

```javascript
// Frida hook，搜索所有 SP 中的 refresh 相关 key
Java.use("android.app.SharedPreferencesImpl").getString.implementation = function(key, defValue) {
    var value = this.getString(key, defValue);
    if (key && key.toString().toLowerCase().indexOf("refresh") !== -1) {
        console.log("[SP] key=" + key + " value=" + value);
    }
    return value;
};
```

**方案 B：直接读 SP 文件**

```bash
# App 的 SharedPreferences 存储路径
adb shell run-as tv.danmaku.bili cat /data/data/tv.danmaku.bili/shared_prefs/*.xml | grep -i "refresh\|token"
```

> 注意：`run-as` 需要 debuggable 的 App，或者用 root 权限直接读。
> 我们的设备已 root（Magisk），可以直接 `adb shell su -c "cat ..."`。

**方案 C：重新登录抓完整流程**

退出登录 → 重新扫码登录 → Frida 抓包捕获登录响应 → 提取 token_info。

---

## 五、后续逆向计划

目标：**不依赖开源文档，从零逆向实现 ticket 和 access_key 的完整刷新链路**。

### Phase 1：JWT ticket 逆向（验证已知结论）

```
1. Frida hook SP.getString/putString，搜 "eyJ" 前缀
2. 追踪调用栈，找到 ticket 管理类
3. 在该类中找到网络请求 → 确认就是 GenWebTicket 接口
4. 对比开源文档，验证一致性
```

### Phase 2：access_key + refresh_token 逆向

```
1. Hook SP，搜 "refresh" / "token" / "access" 关键词 → 拿到当前的 refresh_token
2. Hook 网络层，观察 App 何时调用 refresh 接口（可能在 access_key 快过期时自动触发）
3. 抓取完整的 refresh 请求和响应
4. Python 复现刷新流程
5. 整合到 auto_comment 脚本中
```

### Phase 3：完整登录流程逆向（可选）

```
1. 退出登录 → 重新扫码/短信登录
2. Frida 抓包捕获登录接口的完整请求和响应
3. 提取 token_info（access_token + refresh_token + expires_in）
4. 实现 Python 自动登录（如果需要的话）
```

---

## 六、参考资料

| 资源 | 链接 | 说明 |
|------|------|------|
| bilibili-API-collect（主仓库） | https://github.com/SocialSisterYi/bilibili-API-collect | B站最全第三方 API 文档 |
| QR 扫码登录文档 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/login/login_action/QR.md | token_info 响应格式 |
| 短信登录文档 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/login/login_action/SMS.md | 含 access_token + refresh_token |
| 密码登录文档 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/login/login_action/password.md | RSA 加密 + 登录流程 |
| 登录状态查询 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/login/login_info.md | 检查 token 是否有效 |
| Cookie 刷新文档 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/login/cookie_refresh.md | Web 端 cookie 续期 |
| APP 签名文档 | https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/docs/misc/sign/APP.md | appkey + sign 算法 |
| Bilibili-Toolkit（开源实现） | https://github.com/Hsury/Bilibili-Toolkit/blob/master/bilibili.py | refresh_token 调用示例代码 |
| bilibili-live-tools（开源实现） | https://github.com/Dawnnnnnn/bilibili-live-tools/blob/master/login.py | 登录 + token 刷新实现 |
| access_key 获取讨论 | https://github.com/SocialSisterYi/bilibili-API-collect/issues/676 | 社区讨论现有获取方式 |

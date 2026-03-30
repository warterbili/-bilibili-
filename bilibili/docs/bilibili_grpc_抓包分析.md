# B站评论接口抓包分析

## 问题现象

使用 Charles 或 ProxyPin 对 B站安卓 App 抓包时：

- B站其他请求（首页、视频信息、搜索等）**可以正常抓到**
- 唯独**发表评论的请求**完全不显示，既不报错也不显示 unknown

---

## 原因分析

### 第一层误解：SSL Pinning？

很多人第一反应是 SSL Pinning 导致的，但 SSL Pinning 的表现是：

```
Charles 里能看到连接记录，但显示 unknown 或 SSL 报错
```

而我们的现象是**什么都没有**，说明不是 SSL Pinning，而是协议层面的问题。

---

### 真正原因：评论接口使用 gRPC 协议

B站评论发送接口走的是 **gRPC + Protobuf** 协议，而不是普通的 HTTPS REST API。

```
普通接口（能抓到）：
  App → HTTP/1.1 + JSON → Charles → 服务器
  Charles 完美支持，正常显示

评论接口（抓不到）：
  App → gRPC (HTTP/2) + Protobuf 二进制 → Charles → 服务器
  Charles 对 HTTP/2 支持残缺，静默失败，什么都不显示
```

**B站 gRPC 服务端点：**
- `grpc.biliapi.net`（原生 gRPC 协议）
- `app.bilibili.com`（兼容入口）

请求头中包含多个二进制 Metadata，如 `x-bili-restriction-bin`、`x-bili-locale-bin` 等，本身也是 Protobuf 序列化后 Base64 编码的内容。

---

### 各工具对 gRPC 的支持情况

| 工具 | 能否抓 gRPC | 说明 |
|------|------------|------|
| Charles | 基本不行 | HTTP/2 支持残缺，gRPC 静默丢弃 |
| ProxyPin | 不行 | 同样问题 |
| Fiddler Classic | 不行 | 不支持 HTTP/2 |
| Fiddler Everywhere（付费） | 部分支持 | 对 HTTP/2 支持更好 |
| mitmproxy（新版） | 部分支持 | HTTP/2 支持比 Charles 好 |
| **Wireshark + tcpdump** | **能抓原始包** | 需要配置 proto 文件解析 |
| **Frida Hook** | **最彻底** | 直接 Hook 发包函数，绕过所有协议层 |

---

## 后续解决方案

### 方案一：tcpdump + Wireshark 底层抓包（已实践验证）

#### 环境准备

手机需要 root，使用静态编译的 tcpdump 二进制：

- 下载地址：[androidtcpdump.com 64位版本](https://www.androidtcpdump.com/android-tcpdump/downloads64bit)
- 当前最新版：4.99.6 / libpcap 1.10.6（2025年12月）

```bash
# 推入手机并赋予执行权限
adb push tcpdump /data/local/tmp/tcpdump
adb shell chmod +x /data/local/tmp/tcpdump

# 验证是否正常运行
adb shell /data/local/tmp/tcpdump --version
```

#### 正确的抓包流程

> **关键**：必须先 force-stop B站，再开始抓包，否则 gRPC 长连接已建立，抓不到握手包

**第1步：强制停止 B站**
```bash
adb shell am force-stop tv.danmaku.bili
```

**第2步：终端1 启动抓包**
```bash
adb shell su -c "/data/local/tmp/tcpdump -i any -w /sdcard/bili_grpc.pcap"
```

**第3步：打开 B站，发评论**

**第4步：终端2 正常终止（重要：不能直接 Ctrl+C，否则文件截断损坏）**
```bash
# 用 pkill 发送 SIGINT，tcpdump 正常刷盘退出
adb shell su -c "pkill -2 tcpdump"
```

**第5步：拉取文件**
```bash
adb pull /sdcard/bili_grpc.pcap "C:\lsd_project\app_reverse\安卓底层抓包\"
```

> **踩坑记录**：在 Windows 下直接 Ctrl+C 只是断开了 adb 连接，tcpdump 进程被强制杀死，pcap 文件末尾被截断，Wireshark 打开时报 `The capture file appears to have been cut short in the middle of a packet`。正确做法是开第二个终端用 `pkill -2` 终止。

#### Wireshark 分析

**过滤 B站所有 TLS 域名：**
```
tls.handshake.extensions_server_name contains "bili"
```

**直接过滤 gRPC 端点：**
```
tls.handshake.extensions_server_name == "grpc.biliapi.net"
```

#### 实践结果

抓包成功，确认 B站 App 连接的所有域名：

| 域名 | 用途 |
|------|------|
| `api.bilibili.com` | 主 API |
| `app.bilibili.com` | App API |
| `grpc.biliapi.net` | **gRPC 接口（评论）** |
| `broadcast.chat.bilibili.com` | 弹幕聊天 |
| `cm.bilibili.com` | 推送 |
| `data.bilibili.com` | 数据上报 |
| `dataflow.biliapi.com` | 数据上报 |
| `gaoneng.bilibili.com` | 高能进度条 |
| `line1-log.biligame.net` | 日志 |

抓到的 `grpc.biliapi.net` 握手包示例：
```
Frame 407  16:33:13  192.168.2.2 → 117.21.179.19  TLSv1.3  Client Hello (SNI=grpc.biliapi.net)
Frame 442  16:33:13  192.168.2.2 → 117.21.179.18  TLSv1.3  Client Hello (SNI=grpc.biliapi.net)
Frame 7686 16:33:38  192.168.2.2 → 116.207.163.66 TLSv1.3  Client Hello (SNI=grpc.biliapi.net)
```

Frame 407/442 是 App 启动时建立的连接，Frame 7686 是发评论时触发的新连接。

**局限性**：流量全部是 TLS 密文，能确认流量存在但看不到内容，需要进一步解密。

#### 为什么网页端能抓到，App 端抓不到？

```
网页端：每次发评论 → 新建 HTTP/1.1 连接 → Charles 介入握手 → 抓到
App 端：启动时建立 gRPC 长连接（HTTP/2）→ 发评论只是在已有连接上新开 Stream
        → Charles 没有介入机会 → 什么都看不到
```

Charles 的工作原理是拦截新连接握手，已有连接上的新数据流它完全不知道。
tcpdump 工作在网卡层，不管新旧连接，所有字节都能抓到（但是密文）。

---

### 方案二：mitmproxy（比 Charles 更好的 HTTP/2 支持）

```bash
pip install mitmproxy

# 启动，支持 HTTP/2
mitmproxy --mode regular --ssl-insecure
```

对 gRPC over HTTP/2 的支持优于 Charles，值得尝试。

---

### 方案三：Frida Hook OkHttp（推荐，最彻底）

B站使用 OkHttp 作为网络库，直接 Hook 发包函数，在数据序列化之前拦截，不受协议限制。

```javascript
// Hook OkHttp 的 execute/enqueue，打印所有请求
Java.perform(function () {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    // ... Hook 逻辑
});
```

**前提**：需要先绕过 B站的反 Frida 检测机制（`libmsaoaidsec.so`）。

---

### 方案四：绕过 B站反 Frida 检测

B站 v7.76.0+ 在 `libmsaoaidsec.so` 中通过 `dlsym` 获取 `pthread_create` 来启动检测线程。

绕过思路：Hook `dlsym`，当调用方是 `libmsaoaidsec.so` 时，返回一个空函数指针，让检测线程无法启动。

```bash
# 绕过后正常注入
frida -U -f tv.danmaku.bili -l bypass.js
```

参考：[看雪论坛 - 绕过最新版bilibili反frida机制](https://bbs.kanxue.com/thread-281584.htm)

---

## bilibili-API-collect 下架事件

### 事件经过

**2026年1月28日**，GitHub 上最知名的 B站第三方 API 文档项目 `SocialSisterYi/bilibili-API-collect`（17,160 stars）收到 B站委托律师的警告函。

律师函指控内容：
> "通过技术手段对哔哩哔哩平台非公开的API接口及其调用逻辑、参数结构、访问控制及安全认证机制进行系统性收集、整理，并以技术文档、代码示例等形式向不特定公众传播"

维护者当天宣布即日起**停止维护并清空代码**，仓库已 Archive。

### 评论接口简要记录（网页端）

网页端发送评论接口（供参考，安卓端走 gRPC 不同）：

- **端点**：`POST https://api.bilibili.com/x/v2/reply/add`
- **主要参数**：`oid`（视频ID）、`type`（1=视频）、`message`（内容）、`csrf`（CSRF token）
- **认证**：需要 `SESSDATA` Cookie，部分接口需 WBI 签名（`w_rid` + `wts`）

### 现存镜像备份

原仓库虽然被清空，以下镜像仍可访问：

| 镜像地址 | 说明 |
|----------|------|
| [lxb007981.github.io/bilibili-API-collect](https://lxb007981.github.io/bilibili-API-collect/) | 静态网站镜像，**评论区文档完整** |
| [alittlehuaji/bilibili-api-collect-mirror](https://github.com/alittlehuaji/bilibili-api-collect-mirror) | GitHub 镜像，含 grpc_api 目录 |
| [rinnein/bilibili-API-collect](https://github.com/rinnein/bilibili-API-collect) | fork 版本 |
| [Gitee 镜像](https://gitee.com/wt180250/bilibili-API-collect) | 国内 Gitee 备份 |

> 注：gRPC 相关的 proto 定义在各镜像的 `grpc_api/` 目录下。

---

## 参考资料

- [看雪论坛 - 绕过最新版bilibili app反frida机制](https://bbs.kanxue.com/thread-281584.htm)
- [Medium - How We Cracked Bilibili's "Impenetrable" gRPC API (2026/01)](https://medium.com/@muushroomking/how-we-cracked-bilibilis-impenetrable-grpc-api-when-ai-and-old-maps-failed-us-0164c0261d7f)
- [易姐的博客 - bilibili-API-collect永久停止维护公告](https://shakaianee.top/archives/1074/)
- [新浪财经 - B站API项目收律师函事件](https://t.cj.sina.com.cn/articles/view/1826017320/6cd6d02802001j9ta)
- [CSDN - gRPC通信解析：从Unary到BidirectionalStream的抓包实战](https://blog.csdn.net/luo15242208310/article/details/122911526)
- [raingray Blog - App 抓 HTTP 请求常见解决方案](https://www.raingray.com/archives/4228.html)

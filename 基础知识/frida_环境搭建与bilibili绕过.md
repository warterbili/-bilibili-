# Frida 环境搭建与绕过 B站反检测全记录

## 概述

本文记录从零搭建 Frida 环境，到成功绕过 B站 `libmsaoaidsec.so` 反 Frida 检测的完整过程，包括走过的弯路和每一步的思考方式。

目标设备：小米 9（cepheus），PixelExperience 13.0，已 root

---

## 一、Frida 是什么

Frida 由两部分组成，缺一不可：

| 组件 | 运行位置 | 作用 |
|------|---------|------|
| `frida-tools`（Python 包） | PC | 提供 `frida`、`frida-ps` 等命令行工具 |
| `frida-server`（二进制） | 手机 | 在目标设备上执行 Hook 操作 |

**两者版本必须严格一致**，否则连接失败。

Frida 脚本语言是 **JavaScript**（不是 Java），脚本运行在注入的进程内，通过 Frida 提供的 JS API（如 `Interceptor.attach`）操控目标进程。

---

## 二、环境搭建

### PC 端安装 frida-tools

```bash
pip install frida-tools
```

安装完成后确认版本：

```bash
frida --version
# 输出：17.7.3
```

> 安装时可能出现其他包的兼容性警告（如 `w3lib`、`websockets`），不影响 frida 正常使用，忽略即可。

---

### 手机端安装 frida-server

**下载地址：** `https://github.com/frida/frida/releases/tag/17.7.3`

找到对应架构的文件：**`frida-server-17.7.3-android-arm64.xz`**

> 小米 9 是 arm64 架构，务必选 `android-arm64`，不要选 `frida-core-devkit`（那是开发 SDK）。

解压 `.xz` 后得到单个二进制文件，重命名为 `frida-server`，放到：

```
C:\Users\admin\AppData\frida\frida-server
```

> **注意**：解压后是单个文件，不是文件夹。重命名去掉版本号是为了方便后续命令输入，Linux/Android 可执行文件不需要扩展名。

推入手机并赋予执行权限：

```bash
adb push "C:\Users\admin\AppData\frida\frida-server" /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
```

---

### 启动 frida-server

```bash
adb shell su -c "/data/local/tmp/frida-server &"
```

---

### 验证连接

```bash
frida-ps -U
```

输出进程列表说明连接成功。可以看到 B站进程：

```
14194  tv.danmaku.bili
15402  哔哩哔哩
```

---

## 三、初次注入 B站——被检测到

直接注入 B站：

```bash
frida -U -f tv.danmaku.bili
```

输出：

```
Spawned `tv.danmaku.bili`. Resuming main thread!
[MI 9::tv.danmaku.bili ]-> Process terminated
```

`Process terminated` 说明 B站检测到了 Frida，主动杀死了自身进程。

---

## 四、B站反 Frida 检测机制详解

### 4.0 我们是怎么知道是 libmsaoaidsec.so 在搞鬼的

这是一个很重要的方法论问题：面对一个未知 App 的反调试，**怎么定位到具体是哪个 so 在做检测**？

我们的实际过程分两步：

#### 第一步：网络搜索（最快）

注入 B站后立刻 `Process terminated`，第一反应是搜索：

```
bilibili frida process terminated
bilibili 反frida 绕过
```

在看雪论坛找到专门分析这个问题的文章，明确指出是 `libmsaoaidsec.so`。

> **经验：** 知名 App 的反调试机制往往已经被人分析过，先搜索可以节省大量时间。搜索关键词：`App名 + frida + bypass` 或 `App名 + 反调试`，优先看看雪论坛、GitHub、Medium。

#### 第二步：绕过成功后得到验证

绕过脚本成功运行后，控制台输出确认了是哪个 so：

```
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
```

> **注意**：这是绕过成功之后才看到的。绕过前 app 直接 `Process terminated`，什么都没打印。所以我们实际上是先靠搜索确定了目标，脚本输出只是事后验证。

#### 如果没有公开资料，如何在绕过前定位嫌疑 so

写一个**纯侦察脚本**，不做任何拦截，只打印 dlsym 的调用者。app 虽然还是会崩，但崩之前的日志会先刷出来：

```javascript
// 纯侦察：不拦截，只记录 dlsym 调用来源
var libdl = Process.findModuleByName("libdl.so");
var dlsymAddr = null;
libdl.enumerateExports().forEach(function(exp) {
    if (exp.name === "dlsym") dlsymAddr = exp.address;
});

Interceptor.attach(dlsymAddr, {
    onEnter: function(args) {
        try { this.symbol = args[1].readCString(); } catch(e) { this.symbol = ""; }
    },
    onLeave: function(retval) {
        var mod = Process.findModuleByAddress(this.returnAddress);
        console.log("dlsym(\"" + this.symbol + "\") from " + (mod ? mod.name : "unknown"));
    }
});
```

app 崩溃前会输出所有 dlsym 调用记录，**密集调用 `pthread_create` 的那个模块就是嫌疑人**，再针对它写绕过逻辑。

#### 如果两种方式都不够用：自己枚举 + 排查

对于没有公开资料的冷门 App，可以用以下脚本枚举所有已加载的可疑模块：

```javascript
// 列出所有加载的 native 模块，找可疑的
Process.enumerateModules().forEach(function(mod) {
    var name = mod.name.toLowerCase();
    // 过滤出安全/保护类 so
    if (name.includes("sec") || name.includes("shield") ||
        name.includes("protect") || name.includes("guard") ||
        name.includes("safe") || name.includes("check")) {
        console.log("[!] 可疑模块: " + mod.name + " @ " + mod.base + " size=" + mod.size);
    }
});
```

同时 hook dlsym 打印所有调用者，看哪个模块在密集调用 `pthread_create`：

```javascript
Interceptor.attach(dlsymAddr, {
    onEnter: function(args) {
        try { this.symbol = args[1].readCString(); } catch(e) { this.symbol = ""; }
    },
    onLeave: function(retval) {
        var mod = Process.findModuleByAddress(this.returnAddress);
        var modName = mod ? mod.name : "unknown";
        // 打印所有 dlsym 调用，观察哪个模块行为可疑
        console.log("dlsym(\"" + this.symbol + "\") called from " + modName);
    }
});
```

运行后观察输出，密集调用 `pthread_create`、`strstr`、`open` 的模块就是嫌疑人。

---

### 4.1 libmsaoaidsec.so 的真实身份

名字拆开：**MSA + OAID + Sec**

- **MSA**：移动安全联盟（Mobile Security Alliance），中国信通院牵头组建的行业组织
- **OAID**：开放匿名设备标识符（Open Anonymous Device Identifier），国内替代 IMEI 的广告追踪 ID 方案
- **Sec**：Security

所以这个 so 的**本职工作是设备指纹采集**（配合 OAID 方案），**反 Frida 是附带的防篡改功能**，目的是防止设备指纹被伪造。B站集成它既用于广告归因，也用于反作弊（防刷量、防多开）。

被 B站、爱奇艺、优酷等多个国内大厂集成，因此绕过方法具有**通用性**——搞定了 B站，其他集成同一 SDK 的 App 也能用同样方式绕过。

**怎么直接看出 App 集成了哪些第三方 SDK：**

APK 就是个 ZIP，解压后 `lib/arm64-v8a/` 下的所有 `.so` 文件一览无余：

```bash
# 解压 apk 查看
unzip tv.danmaku.bili.apk -d bili_apk
ls bili_apk/lib/arm64-v8a/
```

或者用工具直接打开，无需解压。

---

### 4.2 识别第三方 SDK 和加固的工具

#### MT管理器（手机端，最方便）

安卓上最流行的逆向辅助工具，直接在手机上打开 APK：

- 查看 `lib/` 下所有 so 文件 → 识别安全 SDK
- 查看 `AndroidManifest.xml` → 找 Application 类名判断是否加壳
- 内置 DEX 查看器 → 浏览 Java 代码结构

#### APKiD（PC 端，最专业）

专门识别加固、混淆、反调试特征的命令行工具：

```bash
pip install apkid
apkid tv.danmaku.bili.apk
```

输出示例：

```
[+] tv.danmaku.bili.apk
 |-> anti_vm : Build.FINGERPRINT check
 |-> compiler : r8 (more likely), d8
 |-> packer : Tencent Legu  ← 加固厂商
```

#### jadx（PC 端）

反编译 APK 为 Java 代码，在代码中搜索 `loadLibrary` 可以看到所有 native 库加载：

```java
System.loadLibrary("msaoaidsec");  // ← 就能看到
System.loadLibrary("ijkffmpeg");
```

---

### 4.3 常见第三方安全 SDK 速查表

| so 文件名 | 来源 | 主要功能 |
|----------|------|---------|
| `libmsaoaidsec.so` | 移动安全联盟 OAID | 设备指纹 + 反调试 |
| `libsgmain.so` | 阿里聚安全 | 反调试 + 完整性校验 |
| `libNSaferOnly.so` | 网易易盾 | 反外挂 + 反调试 |
| `libshield.so` | 同盾科技 | 设备风控 |
| `libtprt.so` | 腾讯手游保护 | 反外挂 |

---

### 4.4 常见加固 SDK 速查表

| so / 特征 | 加固厂商 | 说明 |
|----------|---------|------|
| `libjiagu.so` | 360加固保 | 常见于工具类 App |
| `libshell-super.*.so` | 腾讯乐固 | 游戏类常见 |
| `libDexHelper.so` | 梆梆加固 | |
| `libprotectClass.so` | 爱加密 | |
| Application 类名 = `com.stub.StubApp` | 各类壳 | 被壳替换了真实 Application |

---

### 4.2 Frida 注入后留下哪些痕迹

理解检测之前，先要知道 Frida 注入会在进程中留下什么痕迹：

| 痕迹类型 | 具体内容 | 说明 |
|---------|---------|------|
| 内存映射 | `/proc/self/maps` 中出现 `frida-agent` | frida-agent.so 被注入进内存 |
| 文件描述符 | `/proc/self/fd` 中出现 frida 相关管道 | Frida 通信用的 Unix socket |
| 端口 | 本地监听 `27042` 端口 | frida-server 默认端口 |
| 线程名 | `/proc/self/task/*/comm` 出现 `gmain`、`gdbus` 等 | GLib 主循环线程，frida-agent 引入 |
| 符号 | 内存中存在 `frida_agent_main` 等符号 | frida-agent 导出函数 |

---

### 4.3 libmsaoaidsec.so 的具体检测流程

```
App 启动
    ↓
System.loadLibrary("msaoaidsec")  ← Java 层触发 so 加载
    ↓
libmsaoaidsec.so 的 .init_array 执行（so 初始化代码）
    ↓
【关键步骤】调用 dlsym(RTLD_DEFAULT, "pthread_create")
    → 动态获取 pthread_create 函数指针
    ↓
用 pthread_create 启动 1~3 个检测线程（实际抓到 3 次调用）
    ↓
检测线程持续轮询以下检测点：
    ├── 读取 /proc/self/maps → 搜索 "frida" 字符串
    ├── 读取 /proc/self/maps → 搜索 "gum-js-loop" 字符串
    ├── 尝试连接 127.0.0.1:27042 → 检测 frida-server 端口
    ├── 读取 /proc/self/fd/* → 检测 frida 管道
    └── 检测 /proc/self/status 的 TracerPid → 检测是否被 ptrace 调试
    ↓
任意一项命中 → kill(getpid(), SIGKILL) 或 exit()
```

**我们实际观察到的现象验证了这个流程：**

```
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so  ← 第1个检测线程
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so  ← 第2个检测线程
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so  ← 第3个检测线程
```

libmsaoaidsec.so 尝试创建了 3 个检测线程，全部被我们拦截。

---

### 4.4 为什么用 dlsym 动态获取，而不是直接调用 pthread_create

这是一个对抗静态分析的设计：

```
直接调用（容易被发现）：
    ELF 导入表中明确写着 "pthread_create"
    → 逆向工程师一眼就能看到
    → 用 Interceptor.attach(pthread_create, ...) 就能拦截
    → 被绕过的成本很低

动态调用（更难对抗）：
    ELF 导入表中只有 "dlsym"（很正常，很多库都用）
    → 调用时机和参数在运行时才确定
    → 静态分析无法直接看出调用了 pthread_create
    → 需要分析 dlsym 的参数才能知道
```

这是常见的**反静态分析技巧**，在高对抗场景下还会进一步把字符串 `"pthread_create"` 也加密，运行时解密后再传给 dlsym。

---

### 4.5 常见反 Frida 检测手段汇总（通用参考）

以下是逆向安卓 App 时常见的反 Frida 技术，不限于 libmsaoaidsec.so：

#### 检测类型一：内存扫描（最常见）

```c
// 读取 /proc/self/maps，搜索特征字符串
FILE *fp = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "frida"))   → 检测到
    if (strstr(line, "gum-js"))  → 检测到
    if (strstr(line, "linjector")) → 检测到
}
```

**绕过思路：** Hook `fopen` 或 `read`，当路径是 `/proc/self/maps` 时过滤返回内容中的 frida 相关行。

---

#### 检测类型二：端口扫描

```c
// 尝试连接 frida-server 默认端口
int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, "127.0.0.1:27042", ...);
if (connect 成功) → 检测到 frida-server
```

**绕过思路：** 修改 frida-server 启动端口（`-l 0.0.0.0:端口号`），或 Hook `connect` 拦截特定端口的连接。

---

#### 检测类型三：线程名检测

```c
// 遍历 /proc/self/task/*/comm 检测特征线程名
"gmain"       ← GLib 主循环（frida-agent 引入）
"gdbus"       ← GLib D-Bus（frida-agent 引入）
"gum-js-loop" ← Frida JS 引擎线程
"pool-frida"  ← Frida 线程池
```

**绕过思路：** Hook `prctl(PR_SET_NAME, ...)` 修改 frida 线程名，或 Hook `/proc` 相关读取。

---

#### 检测类型四：符号检测

```c
// 在内存中搜索 frida 导出函数名
dlsym(RTLD_DEFAULT, "frida_agent_main");
if (结果非NULL) → 检测到
```

**绕过思路：** Hook `dlsym`，对 frida 相关符号名返回 NULL。

---

#### 检测类型五：反调试（ptrace）

```c
// 读取 /proc/self/status 的 TracerPid 字段
// 正常进程 TracerPid = 0
// 被调试时 TracerPid = 调试器的 PID
if (TracerPid != 0) → 被调试，退出
```

**绕过思路：** Hook `fopen("/proc/self/status")` 或 `read`，修改返回内容中的 TracerPid 为 0。

---

#### 检测类型六：时间差检测（反动态分析）

```c
// 检测某段代码执行时间是否异常长
// 正常执行几微秒，调试/插桩时会变慢几倍
clock_gettime(t1);
// 执行一段代码
clock_gettime(t2);
if (t2 - t1 > 阈值) → 正在被调试
```

**绕过思路：** Hook `clock_gettime`，返回固定的时间差。

---

### 4.6 检测对抗升级路线

```
第一代：直接 strstr("/proc/self/maps", "frida")
    ↓ 绕过：把 frida-server 改名

第二代：dlsym 动态调用 + 字符串混淆
    ↓ 绕过：Hook dlsym（本文方案）

第三代：字符串加密 + 多线程并发检测 + 时间差检测
    ↓ 绕过：需要结合 IDA 静态分析找到解密函数后 patch

第四代：TEE（可信执行环境）内检测，结果加密上报
    ↓ 绕过：极难，需要特定硬件环境
```

B站目前（v7.76.0+）处于第二代，用 dlsym 间接调用 + 多线程，我们用 dlsym Hook 方案可以绕过。

---

## 五、绕过脚本的编写历程（含弯路）

### 第一版：逻辑正确，但 JS 报错

**思路：** Hook `android_dlopen_ext` 监听 `libmsaoaidsec.so` 加载，加载时再 hook `dlsym`。

```javascript
["dlopen", "android_dlopen_ext"].forEach(function(fname) {
    var fn = Module.findExportByName(null, fname);
    if (!fn) return;
    Interceptor.attach(fn, { ... });
});
```

**报错：**
```
TypeError: not a function
    at <anonymous> (bypass.js:34)
    at forEach (native)
```

**弯路分析：**

`!fn` 判断有问题。在 Frida 中，`Module.findExportByName` 找不到时返回的不一定是 JS `null`，可能是 `NativePointer(0x0)`——一个地址为 0 的指针对象。对象是 truthy，所以 `!fn` 不会触发，但把 0x0 传给 `Interceptor.attach` 就报错了。

**修复：改用 `fn.isNull()` 检查**

---

### 第二版：`android_dlopen_ext` 根本 hook 不上

**报错：**
```
[-] Failed to hook android_dlopen_ext: TypeError: not a function
[-] Failed to hook dlopen: TypeError: not a function
```

**弯路分析：**

在 Android 13 上，`dlopen` 和 `android_dlopen_ext` 在 `libdl.so` 中只是跳转到 `linker64` 的 **PLT stub**（几条指令的跳板），Frida 无法对这种极短的跳板函数进行 `Interceptor.attach`。

同时发现还有另一个逻辑问题：用 `onLeave` 中 hook dlsym 时机太晚——`libmsaoaidsec.so` 的初始化代码在 `android_dlopen_ext` 内部执行，等 `onLeave` 触发时 dlsym 已经被调过了。应该在 `onEnter` 时就 hook。

但由于 android_dlopen_ext 本身就 hook 不上，这条路行不通。

**新思路：** 用 `-f`（spawn）模式启动时，脚本在 app 任何代码执行之前注入，根本不需要 hook dlopen——直接在脚本启动时 hook dlsym 就够了，时机完全来得及。

---

### 第三版：创建假函数方式错了

改成直接 hook dlsym，但假函数用 `Memory.writeByteArray` 手写 ARM64 机器码：

```javascript
var fakeFunc = Memory.alloc(8);
Memory.protect(fakeFunc, 8, 'rwx');
Memory.writeByteArray(fakeFunc, [0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]);
```

**报错：**
```
TypeError: not a function
    at <eval> (bypass.js:14)
```

**弯路分析：**

`Memory.writeByteArray` 这个 API 在新版 Frida 中已经变更，正确写法是 `ptr.writeByteArray(bytes)`（在 NativePointer 对象上调用）。

此外手写机器码依赖 CPU 架构（ARM64），不够通用，也容易出错。

**修复：改用 `NativeCallback` 创建假函数，Frida 自动处理架构差异**

```javascript
var fakeFunc = new NativeCallback(function() {
    return 0;
}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
```

---

### 第四版：dlsym hook 失败，原因不明

**报错：**
```
[-] Failed to hook dlsym: TypeError: not a function
```

**弯路分析：**

运行诊断脚本后发现：

- `Module.findExportByName("libdl.so", "dlsym")` 返回的地址——**hook 失败**
- `libdl.so.enumerateExports().dlsym.address` 返回的地址——**hook 成功**

根本原因：`Module.findExportByName` 通过动态链接器查找符号，返回的是 **PLT 跳转 stub** 的地址；而 `enumerateExports()` 直接解析 ELF 导出表，返回的是**真实函数地址**。两个地址不同，前者不可 hook。

**诊断脚本（关键信息）：**

```
[*] libdl.so -> dlsym @ 0x786ce8d044 type=function
    [+] 可以 hook!

linker64 base: 0x786ed24000
  __loader_dlsym @ 0x786ed5b358
```

---

### 第五版（最终版）：绕过成功

**关键修复：** 用 `enumerateExports()` 获取 dlsym 真实地址

```javascript
var libdl = Process.findModuleByName("libdl.so");
libdl.enumerateExports().forEach(function(exp) {
    if (exp.name === "dlsym") addr = exp.address;
});
```

**成功输出：**

```
[+] dlsym real address: 0x786ce8d044
[+] dlsym hooked successfully
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so  ← 拦截成功
[+] fake pthread_create called, suppressed                  ← 假函数执行
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
[+] Blocked dlsym("pthread_create") from libmsaoaidsec.so
[+] fake pthread_create called, suppressed
```

没有 `Process terminated`，B站正常启动，Frida 成功驻留进程。

`libmsaoaidsec.so` 尝试了 3 次获取 `pthread_create`，全部被拦截。

---

## 六、诊断脚本（排查 hook 问题的利器）

文件路径：`C:\lsd_project\app_reverse\bilibili_frida绕过\diagnose.js`

当绕过脚本报错或行为异常时，先跑诊断脚本弄清楚：
1. `Interceptor.attach` 在当前环境是否正常
2. `dlsym` 到底在哪个模块、哪个地址，是否可 hook
3. linker64 有哪些相关导出函数

```javascript
// 诊断脚本：找出 dlsym 的真实位置，以及哪些函数可以被 hook

// 1. 测试 Interceptor.attach 是否能工作（用 malloc 做基准测试）
console.log("=== 测试 Interceptor.attach 是否正常 ===");
try {
    var malloc = Module.findExportByName("libc.so", "malloc");
    Interceptor.attach(malloc, { onEnter: function() {} });
    console.log("[+] libc malloc 可以 hook @ " + malloc);
    Interceptor.detachAll();
} catch(e) {
    console.log("[-] malloc hook 失败: " + e);
}

// 2. 找 dlsym 在所有模块中的位置
console.log("\n=== 查找 dlsym 在哪些模块中 ===");
Process.enumerateModules().forEach(function(mod) {
    try {
        mod.enumerateExports().forEach(function(exp) {
            if (exp.name === "dlsym" || exp.name === "__dl_dlsym" || exp.name === "__dlsym") {
                console.log("[*] " + mod.name + " -> " + exp.name + " @ " + exp.address + " type=" + exp.type);
                try {
                    Interceptor.attach(exp.address, { onEnter: function() {} });
                    console.log("    [+] 可以 hook!");
                    Interceptor.detachAll();
                } catch(e2) {
                    console.log("    [-] hook 失败: " + e2);
                }
            }
        });
    } catch(e) {}
});

// 3. 列出 linker64 的部分 exports（找检测相关的）
console.log("\n=== linker64 导出函数（含 dl 关键词）===");
var linker = Process.findModuleByName("linker64");
if (linker) {
    console.log("linker64 base: " + linker.base);
    linker.enumerateExports().forEach(function(exp) {
        if (exp.name.toLowerCase().includes("dlsym") ||
            exp.name.toLowerCase().includes("dlopen")) {
            console.log("  " + exp.name + " @ " + exp.address);
        }
    });
} else {
    console.log("[-] linker64 not found");
}

console.log("\n=== 诊断完成 ===");
```

**使用方式：**

```bash
frida -U -f tv.danmaku.bili -l "C:\lsd_project\app_reverse\bilibili_frida绕过\diagnose.js"
```

**实际输出（Android 13 / PixelExperience 13）：**

```
=== 测试 Interceptor.attach 是否正常 ===
[-] malloc hook 失败: TypeError: not a function    ← libc.so 的 malloc 受保护

=== 查找 dlsym 在哪些模块中 ===
[*] libdl.so -> dlsym @ 0x786ce8d044 type=function
    [+] 可以 hook!                                 ← 这才是真实地址

=== linker64 导出函数（含 dl 关键词）===
linker64 base: 0x786ed24000
  __loader_android_dlopen_ext @ 0x786ed5b094
  __loader_dlopen @ 0x786ed5b18c
  __loader_dlsym @ 0x786ed5b358
```

**关键发现：**
- `Module.findExportByName("libdl.so", "dlsym")` 返回的是 PLT stub，不可 hook
- `enumerateExports()` 返回的 `0x786ce8d044` 才是真实函数地址，可以 hook
- linker64 中的 `__loader_dlsym` 是底层实现（备选 hook 点）

---

## 七、最终绕过脚本（含完整注释）

文件路径：`C:\lsd_project\app_reverse\bilibili_frida绕过\bypass.js`

```javascript
// 绕过 B站 libmsaoaidsec.so 反 Frida 检测
var fakeFunc = new NativeCallback(function() {
    console.log("[+] fake pthread_create called, suppressed");
    return 0;
}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

function findDlsymReal() {
    var libdl = Process.findModuleByName("libdl.so");
    if (!libdl) return null;
    var addr = null;
    libdl.enumerateExports().forEach(function(exp) {
        if (exp.name === "dlsym") addr = exp.address;
    });
    return addr;
}

var dlsymAddr = findDlsymReal();
if (dlsymAddr) {
    Interceptor.attach(dlsymAddr, {
        onEnter: function(args) {
            try {
                this.symbol = args[1].isNull() ? "" : args[1].readCString();
            } catch(e) { this.symbol = ""; }
        },
        onLeave: function(retval) {
            if (this.symbol === "pthread_create" || this.symbol === "pthread_join") {
                var mod = Process.findModuleByAddress(this.returnAddress);
                if (mod && mod.name.indexOf("msaoaidsec") !== -1) {
                    retval.replace(fakeFunc);
                }
            }
        }
    });
}
```

**使用方式：**

```bash
frida -U -f tv.danmaku.bili -l "C:\lsd_project\app_reverse\bilibili_frida绕过\bypass.js"
```

---

## 八、总结：几个通用的 Frida 调试经验

| 问题 | 原因 | 解决方式 |
|------|------|---------|
| `!fn` 判断无效 | NativePointer(0x0) 是 truthy 对象 | 改用 `fn.isNull()` |
| `android_dlopen_ext` 无法 hook | Android 13 linker 保护，PLT stub 太短 | 换思路，不 hook dlopen |
| `Memory.writeByteArray(ptr, bytes)` 失败 | 新版 Frida API 变更 | 改用 `ptr.writeByteArray(bytes)` 或 `NativeCallback` |
| `Module.findExportByName` 返回地址不可 hook | 返回的是 PLT stub，不是真实函数 | 改用 `module.enumerateExports()` |
| `-f` spawn 模式比 attach 更早注入 | spawn 在主线程启动前注入 | 检测绕过优先用 `-f`，不需要 hook dlopen |

---

## 九、后续方向

绕过检测只是第一步，Frida 驻留成功后可以：

1. **Hook OkHttp** → 直接拦截 gRPC 请求，获取明文
2. **Hook BoringSSL `SSL_write`/`SSL_read`** → 导出 TLS session key → 配合 Wireshark 解密

---

## 十、参考资料

- [看雪论坛 - 绕过最新版bilibili app反frida机制](https://bbs.kanxue.com/thread-281584.htm)
- [绕过爱奇艺 libmsaoaidsec.so 的 Frida 检测](https://xiaoeeyu.github.io/2024/08/09/%E7%BB%95%E8%BF%87%E7%88%B1%E5%A5%87%E8%89%BAlibmsaoaidsec-so%E7%9A%84Frida%E6%A3%80%E6%B5%8B/)
- [Frida 官方文档](https://frida.re/docs/home/)

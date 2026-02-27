# B站 sign 算法完整逆向实战（动态+静态联合分析）

> 上接：[sign逆向分析实录.md](./sign逆向分析实录.md)（jadx 静态分析部分）
> 分析日期：2026-02-19
> 工具：Frida 17.7.3 + Ghidra 12.0.3 + Python 3.14
> 目标：不依赖任何公开资料，完全自主地从 libbili.so 还原 sign 的完整加密逻辑

---

## 一、目标与约束

上一篇已经定位到：sign 由 `LibBili.s(SortedMap)` 这个 native 方法计算，实现在 `libbili.so` 里。

本篇要做的：
1. 用 Frida 在运行时找到 `.so` 里的确切函数地址
2. 用 Ghidra 静态读懂函数的计算逻辑
3. 用 Frida 动态确认静态分析中无法读取的加密常量（appSecret、格式字符串）
4. 最终用 Python 完整复现，与抓包验证吻合

---

## 二、难点预判

B站的 `libbili.so` 有三道壁垒，每一道都必须独立突破：

| 壁垒 | 现象 | 影响 |
|------|------|------|
| **Anti-Frida 检测** | 启动后约 3 秒 App 被杀死 | Frida 无法正常工作 |
| **JNI RegisterNatives 动态注册** | Ghidra Exports 里没有 `Java_` 前缀函数 | 找不到 sign 函数入口地址 |
| **OLLVM 控制流平坦化** | 函数变成状态机，逻辑完全不可读 | 无法静态理解算法 |
| **datadiv_decode 字符串加密** | 敏感字符串（格式字符串、appSecret）运行时才解密 | 静态看不到真实值 |

---

## 三、第一关：绕过 Anti-Frida 检测

### 检测原理

B站使用 `libmsaoaidsec.so` 做反调试，核心手段是在 `pthread_create` 里启动检测线程。

检测线程会轮询：
- `/proc/self/maps` — 扫描内存里是否有 `frida` 字符串
- `/proc/self/status` — 检测调试器状态（TracerPid）
- 读 `libart.so` 的函数指针 — 检测是否被 hook

### 绕过方案（bypass.js）

```javascript
// 核心思路：在 libmsaoaidsec.so 加载前，替换它依赖的 dlsym
// 让它拿到的 pthread_create 是一个什么都不做的假函数

var realDlsym = null;
var fakeFunc = new NativeCallback(function() { return 0; }, 'int', []);

// hook libc 的 dlsym
var dlsymAddr = Module.findExportByName(null, "dlsym");
Interceptor.attach(dlsymAddr, {
    onEnter: function(args) {
        this.sym = args[1].readCString();
    },
    onLeave: function(retval) {
        // 只拦截 libmsaoaidsec.so 查询 pthread_create 的调用
        if (this.sym === "pthread_create" && /* 调用方在 libmsaoaidsec.so 内 */) {
            retval.replace(fakeFunc);
        }
    }
});
```

**关键：必须用 spawn 模式（`-f tv.danmaku.bili`）**，注入时机必须在 `libmsaoaidsec.so` 的 `JNI_OnLoad` 执行前，否则检测线程已经启动，绕过无效。

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js"
```

---

## 四、第二关：找到 sign 函数的运行时地址

这是整个逆向过程中最关键的一步，也是最容易被卡住的地方。详细说清楚。

### 4.1 为什么常规方法全部失败

找 JNI 函数地址通常有两条路，B站两条都堵死了：

**路1：Ghidra Exports 搜 `Java_` 前缀**

标准 JNI 静态注册，函数名必须是：
```
Java_com_bilibili_nativelibrary_LibBili_s
```
进 Ghidra → Symbol Tree → Exports，**搜索结果为空**。B站没用静态注册。

**路2：进 `JNI_OnLoad` 找方法表**

`JNI_OnLoad` 确实能找到，但进去之后是 OLLVM 状态机，方法表的地址藏在几十个 `if/else` 跳转里，根本读不出来。

---

### 4.2 RegisterNatives 动态注册原理

B站用的是 JNI 的另一种注册方式。`JNI_OnLoad` 内部大致做了这件事（混淆前的逻辑）：

```c
// App 启动时，JNI_OnLoad 里执行一次
JNINativeMethod methods[] = {
    { "s", "(Ljava/util/SortedMap;)Lxxx/SignedQuery;", (void*)FUN_00109050 },
    { "a", "(Ljava/lang/String;)Ljava/lang/String;",   (void*)FUN_0010xxxx },
    // ... 共 11 个方法
};
env->RegisterNatives(LibBili_class, methods, 11);
```

`FUN_00109050` 就是 sign 函数的真实地址——它没有任何导出，只存在于这个运行时注册表里，Ghidra 静态分析永远看不到这个绑定关系。

---

### 4.3 突破思路：监听注册事件本身

`env->RegisterNatives()` 是 JNI 接口，底层最终调用 ART 虚拟机的 C++ 方法：

```
art::ClassLinker::RegisterNative(Thread*, ArtMethod*, void* fnPtr)
```

**每注册一个 native 方法就调用一次，`args[3]` 就是被注册的函数指针。**

这个函数在 `libart.so`（系统库，无混淆）里，可以直接 hook。等于说：
> 混淆再厉害，注册这一步是绕不过去的——系统必须拿到真实函数指针才能完成绑定。

---

### 4.4 找到正确的符号名

`libart.so` 里的导出符号是 C++ mangled name，不是 JNI 文档里的 `RegisterNatives`。
先用 `find_registernatives.js` 枚举确认：

```javascript
libart.enumerateExports().forEach(function(e) {
    if (e.name.toLowerCase().indexOf("registernative") !== -1)
        console.log(e.name);
});
```

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" -l "C:/lsd_project/app_reverse/bilibili_frida绕过/find_registernatives.js"
```

输出：
```
_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv
```

这是 **C++ Name Mangling**（名称修饰）后的符号，还原后可读形式为：

```
art::ClassLinker::RegisterNative(art::Thread*, art::ArtMethod*, void const*)
```

各段解析：

| 段 | 含义 |
|----|------|
| `_ZN` | C++ 命名空间/类方法的 mangling 前缀 |
| `3art` | 命名空间 `art`（3 = 字符串长度） |
| `11ClassLinker` | 类名 `ClassLinker`（11 = 字符串长度） |
| `14RegisterNative` | 方法名 `RegisterNative`（14 = 字符串长度） |
| `EPNS_6Thread` | 参数1：`art::Thread*` |
| `EPNS_9ArtMethod` | 参数2：`art::ArtMethod*`（代表一个 Java 方法） |
| `EPKv` | 参数3：`void const*`（即 native 函数指针） |

Frida hook 时各参数含义：

```
art::ClassLinker::RegisterNative(
    ClassLinker* self,   // args[0] — C++ this 指针（ClassLinker 实例）
    Thread*      thread, // args[1] — 当前 ART 线程
    ArtMethod*   method, // args[2] — 被注册的 Java native 方法描述符
    void*        fnPtr   // args[3] — 对应的 .so 函数地址 ← 我们要的
)
```

> **为什么这里能拿到真实地址：** 混淆再厉害，ART 最终必须拿到真实函数指针才能完成调用。`args[3]` 就是那个绕不过去的真实值。

---

### 4.5 完整 Hook 实现

```javascript
// hook_sign.js

// 必须在脚本最顶层就 hook，不能等 libbili.so 加载后再做
// 原因：RegisterNatives 在 JNI_OnLoad 里调用，.so 加载时立即执行
//       如果等检测到 libbili.so 再来 hook，注册早已完成，什么都捕获不到
var libart = Process.findModuleByName("libart.so");
var regNativeAddr = null;

libart.enumerateExports().forEach(function(e) {
    if (e.name === "_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv")
        regNativeAddr = e.address;
});

Interceptor.attach(regNativeAddr, {
    onEnter: function(args) {
        var fnPtr = args[3];

        // 顺便触发 libbili.so 地址范围的更新（此时可能刚好在加载）
        if (!libbiliBase) getLibbiliRange();

        // 过滤：只保留地址落在 libbili.so 内存范围的
        if (libbiliBase && inLibbili(fnPtr)) {
            var offset = fnPtr.sub(libbiliBase);
            console.log("[+] 注册: offset=+0x" + offset.toString(16));
            capturedFuncs.push(fnPtr);
        }
    }
});
```

**为什么要用 spawn 模式（`-f tv.danmaku.bili`）：**
脚本必须在 App 任何代码执行前注入。spawn 模式会暂停进程在入口点，等 Frida 脚本完全加载后再继续，确保 `RegisterNative` 的 hook 在 `JNI_OnLoad` 执行前已就绪。

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" -l "C:/lsd_project/app_reverse/bilibili_frida绕过/hook_sign.js"
```

---

### 4.6 实际输出与定位

捕获阶段（App 启动过程中自动输出）：
```
[+] 注册: offset=+0x8fc4   ← 方法 #0
[+] 注册: offset=+0x8fd8   ← 方法 #1
[+] 注册: offset=+0x8fec   ← 方法 #2
[+] 注册: offset=+0x9050   ← 方法 #3
[+] 注册: offset=+0x90ac   ← 方法 #4
... 共 11 个
```

15 秒后对所有 11 个地址逐一附加 Interceptor，发一条评论，Frida 输出多个方法被调用。

---

### 4.6.1 如何从多个调用中确认 sign 函数

**排除法在这里无效。** 实际输出中方法 #3 从 App 启动就开始持续高频触发——加载首页、获取视频信息、发评论，每一个需要签名的 API 请求都调用它。发评论时方法 #3 当然触发了，但不发评论它也在触发。所以无法用"发评论才新增的方法"来缩小范围。

**真正的确认方式：Ghidra 交叉验证 —— 直接看代码结构**

11 个 offset 逐一去 Ghidra 查对应函数，看参数类型和调用链是否与 sign 语义吻合：

```
offset +0x9050 → Ghidra FUN_00109050
    参数：JNIEnv*, jclass, jobject (SortedMap)   ← 与 LibBili.s(SortedMap) 完全吻合
    调用链：→ FUN_0011629c → FUN_001162a8
    FUN_001162a8 内部：调用 MD5_Init / MD5_Update / MD5_Final ← 确认是 sign ✅

其他 offset → 参数类型不匹配（String/int/void），或调用链无 MD5 → 排除
```

方法 #3 高频触发本身也是一个辅助信号：sign 每次发请求都算，频率高符合预期。但这只是辅助，结论来自 Ghidra。

**结论：sign 函数文件偏移 = `+0x9050`，对应 Ghidra 地址 `0x109050`（Ghidra 基址 `0x100000` + `0x9050`）。**

---

### 4.7 这个方法的普适性

**任何使用 `RegisterNatives` 动态注册的 App 都适用这套方法：**

```
1. Hook art::ClassLinker::RegisterNative（libart.so，系统级，无混淆）
2. 过滤 args[3] 地址落在目标 .so 范围内的
3. 收集所有注册的函数指针（通常十几个）
4. 对每个 offset 去 Ghidra 查对应函数的参数类型和调用链
5. 找参数/调用链与目标语义吻合的函数 → 确认地址 ✅
```

> **注意：** 对于 sign 这类全局性函数（所有 API 请求都会调用），排除法（"触发操作后才新增的方法"）无效——它从 App 启动就一直在触发。直接 Ghidra 看代码结构是唯一可靠的确认方式。

本质是把问题从「在混淆代码里找函数地址」转化为「监听系统级的注册事件」——这个事件是混淆绕不过去的。

---

## 五、第三关：Ghidra 静态分析调用链

### 5.1 入口函数 FUN_00109050（JNI 入口）

```c
// 结构非常简单，是个透明转发层
void FUN_00109050(JNIEnv *env, jclass cls, jobject sortedMap) {
    FUN_0011629c(env, sortedMap);
}
```

### 5.2 包装层 FUN_0011629c

```c
// 另一层透传，参数原封不动
void FUN_0011629c(...) {
    FUN_001162a8(env, sortedMap);
}
```

### 5.3 核心函数 FUN_001162a8（OLLVM 状态机）

这里是 OLLVM 重灾区，状态变量 `iVar3` 在 while 循环里跳转。但忽略状态机骨架，只看实际被调用的子函数：

```
FUN_001162a8
    ├─ FUN_00117de4(env, sortedMap)
    │      → 序列化 TreeMap 为 "key=url_encoded_val&..." 字符串
    ├─ FUN_0011605c(appkey_version)
    │      → 查表，返回对应 appSecret 数据块指针
    └─ FUN_00118ff0(output_buf, sorted_params, params_len, secret_ptr)
           → MD5 计算，输出 32 字符 hex sign
```

### 5.4 MD5 计算函数 FUN_00118ff0（可读）

这是整个分析中最关键的函数，即使有 OLLVM 也能读懂逻辑：

```c
void FUN_00118ff0(char *out, char *sorted_params, int len, uint32_t *secret) {
    MD5_CTX ctx;

    FUN_0010ffac(&ctx);                         // MD5_Init
    FUN_0010ffc0(&ctx, sorted_params, len);     // MD5_Update(sorted_params)

    // 4 次循环，每次把一个 uint32_t 格式化为 8 字符 hex
    for (int i = 0; i < 4; i++) {
        char buf[9];
        sprintf(buf, DAT_001d8844, secret[i]);  // DAT_001d8844 = "%08x"（加密，静态不可见）
        FUN_0010ffc0(&ctx, buf, 8);             // MD5_Update(buf)
    }

    byte digest[16];
    FUN_00112dd0(digest, &ctx);                 // MD5_Final

    // 16 次循环，把每个 digest 字节格式化为 2 字符 hex
    for (int i = 0; i < 16; i++) {
        sprintf(out + i*2, DAT_001d8cbc, digest[i]); // DAT_001d8cbc = "%02x"（加密）
    }
}
```

两个 `DAT_` 格式字符串被 datadiv_decode 加密，静态只能看到一个字节（`CE`）。需要动态确认。

### 5.5 序列化函数 FUN_00117de4

通过 JNI 迭代 Java TreeMap，序列化为字符串。在 JNI 里调用了 vtable offset `0x390` 的方法（即 Java 的 URL encoding 方法），对值做 URL 编码。

### 5.6 appSecret 选取函数 FUN_0011605c

根据 appkey 版本返回数据块指针（三个候选地址：`UNK_001c0a60`、`UNK_001c0b90`、`DAT_001c0cc0`）。`FUN_001162a8` 以偏移 `0 / 0x13×4 / 0x26×4 / 0x39×4` 读出 4 个 `uint32_t`——非连续读取是为了防内存 dump 分析。

---

## 六、第四关：动态确认加密常量

静态分析有两个洞：格式字符串和 appSecret。用 Frida 动态填上。

### 6.1 确认格式字符串（hook_sprintf.js）

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" -l "C:/lsd_project/app_reverse/bilibili_frida绕过/hook_sprintf.js"
```

Hook `libc.so` 的 `sprintf`，只打印来自 `libbili.so` 的调用：

```javascript
Interceptor.attach(sprintfAddr, {
    onEnter: function(args) {
        var caller = this.returnAddress;
        if (caller in libbili range) {
            var fmt = args[1].readCString();
            console.log("[sprintf] +0x" + offset + " fmt=\"" + fmt + "\"");
        }
    }
});
```

**输出（发一条评论后）：**

```
[sprintf] caller=+0x190dc  fmt="%08x"   ← 4次，对应 appSecret 的 4 个 uint32_t
[sprintf] caller=+0x192a0  fmt="%02x"   ← 16次，对应 MD5 digest 的 16 个字节
```

**额外发现：**
```
[sprintf] caller=+0x27024  fmt="/proc/%d/status"   ← 反调试！读进程状态
[sprintf] caller=+0x29800  fmt="/proc/%d/maps"     ← 反调试！扫内存映射
```

B站在运行时持续检测自身是否被调试，这两行是 Anti-Frida 检测的证据。

### 6.2 读取 appSecret（hook_appsecret.js）

```bash
frida -U -f tv.danmaku.bili -l "C:/lsd_project/app_reverse/bilibili_frida绕过/bypass.js" -l "C:/lsd_project/app_reverse/bilibili_frida绕过/hook_appsecret.js"
```

直接 Hook `FUN_00118ff0`（文件偏移 `0x18ff0` = Ghidra `0x118ff0 - 0x100000`），读 `args[3]`（4个 uint32_t）：

```javascript
var FILE_OFFSET = 0x18ff0;
Interceptor.attach(libbiliBase.add(FILE_OFFSET), {
    onEnter: function(args) {
        var v0 = args[3].readU32();           // 偏移 0
        var v1 = args[3].add(4).readU32();    // 偏移 4
        var v2 = args[3].add(8).readU32();    // 偏移 8
        var v3 = args[3].add(12).readU32();   // 偏移 12
        console.log("[!!!] appSecret = " + toHex8(v0)+toHex8(v1)+toHex8(v2)+toHex8(v3));
    }
});
```

**输出：**
```
[!!!] appSecret = 560c52ccd288fed045859ed18bffd973
```

| 变量 | uint32_t 值 | `%08x` 输出 |
|------|------------|------------|
| secret[0] | `0x560c52cc` | `560c52cc` |
| secret[1] | `0xd288fed0` | `d288fed0` |
| secret[2] | `0x45859ed1` | `45859ed1` |
| secret[3] | `0x8bffd973` | `8bffd973` |

---

## 七、算法完整还原

综合静态（Ghidra）和动态（Frida）分析，sign 的完整计算逻辑：

```
输入：请求参数 dict（原始未编码值）

Step 1: 按 key 字母序排列（TreeMap 保证）
Step 2: 对每个 value 做 URL 编码（quote(v, safe='')）
Step 3: 拼接为 "key1=val1&key2=val2&..." 字符串
Step 4: MD5_Update(sorted_params)
Step 5: for i in 0..3:
            MD5_Update(sprintf("%08x", secret[i]))
Step 6: MD5_Final → digest[16]
Step 7: for i in 0..15:
            out += sprintf("%02x", digest[i])
Step 8: return out  ← 32字符小写 hex 字符串
```

等价的 Python 实现（`bili_sign.py`）：

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

### 验证

```
计算 sign：83f5e24c3e2a92761f06d274ff412fb2
抓包 sign：83f5e24c3e2a92761f06d274ff412fb2
✅ 完全吻合
```

---

## 八、踩过的坑（避免重蹈）

### 坑1：进程名写错

```bash
# 错：frida-ps 里的显示名
frida -U -n "tv.danmaku.bili" ...

# 对：spawn 模式用包名，attach 模式用 frida-ps 显示的名字
frida -U -f tv.danmaku.bili -l bypass.js --no-pause   # spawn
frida -U -n "哔哩哔哩" -l hook.js                      # attach（不推荐）
```

### 坑2：hook_sign.js v1 用了 Java.perform

```javascript
// ❌ 错误：Java.perform 会修改 ART method table
// B站 ~3秒内检测到并杀死 App
Java.perform(function() {
    var LibBili = Java.use('com.bilibili.nativelibrary.LibBili');
    LibBili.s.implementation = function(...) { ... };
});

// ✅ 正确：纯 Native Hook，不触碰 ART method table
Interceptor.attach(targetAddr, { onEnter: function(args) { ... } });
```

### 坑3：RegisterNatives 的符号名

```javascript
// ❌ 错：JNI 文档里的 Java 侧名字，在 libart.so 导出表里找不到
libart.findExportByName("RegisterNatives")

// ✅ 对：C++ mangled name
"_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv"
// 用 find_registernatives.js 枚举 libart.enumerateExports() 确认
```

### 坑4：Ghidra 地址 vs 文件偏移

```
Ghidra 加载基址：0x100000
Ghidra 显示地址：0x118ff0
文件偏移       = 0x118ff0 - 0x100000 = 0x18ff0
运行时地址     = libbili.so base + 0x18ff0
```

### 坑5：参数值需要 URL 编码

```python
# ❌ 错：直接拼接原始值
sorted_params = "&".join(f"{k}={v}" for k,v in sorted(params.items()))
# "message=哈哈&statistics={"appId":1,...}" → 算出的 sign 不对

# ✅ 对：对 value 做 URL 编码
sorted_params = "&".join(f"{k}={quote(str(v), safe='')}" for k,v in sorted(params.items()))
# "message=%E5%93%88%E5%93%88&statistics=%7B%22appId%22%3A1..." → 正确
```

这个坑是最后通过穷举编码方案（不编码/全编码/部分编码）发现的，根本原因是 `FUN_00117de4` 的 JNI 序列化会对非 ASCII 字符和特殊符号做 URL 编码。

---

## 九、方法论总结

```
目标：已知 sign 字段 → 还原完整算法

1. 静态分析（jadx）
   ├─ 从 API URL 路径找接口定义
   └─ 沿调用链追到 native 函数声明（LibBili.s）

2. 动态分析（Frida）- 找地址
   ├─ bypass.js 绕过 Anti-Frida
   ├─ hook art::ClassLinker::RegisterNative 捕获所有 native 函数地址
   └─ 触发 sign 操作，定位到具体函数（offset +0x9050）

3. 静态分析（Ghidra）- 读逻辑
   ├─ 从 +0x9050 开始，沿调用链追进去
   ├─ 识别 OLLVM 骨架，忽略状态机，关注子函数调用
   └─ 读懂 MD5 计算函数 FUN_00118ff0

4. 动态分析（Frida）- 填常量
   ├─ hook_sprintf.js → 确认 "%08x" 和 "%02x" 格式字符串
   └─ hook_appsecret.js → 读出 4 个 uint32_t appSecret

5. 还原 + 验证（Python）
   └─ make_sign() 与抓包 sign 完全吻合 ✅
```

**核心经验：静态分析搞清楚逻辑结构，动态分析填上静态看不到的加密常量。两者缺一不可。**

---

## 十、产出文件

| 文件 | 用途 |
|------|------|
| `bilibili_frida绕过/bypass.js` | 绕过 Anti-Frida 检测（必须最先加载） |
| `bilibili_frida绕过/find_registernatives.js` | 确认 libart.so 中 RegisterNative 的真实符号名 |
| `bilibili_frida绕过/hook_sign.js` | 捕获 libbili.so 所有 native 方法地址，定位 sign 函数 |
| `bilibili_frida绕过/hook_appsecret.js` | 动态读取 4 个 uint32_t appSecret |
| `bilibili_frida绕过/hook_sprintf.js` | 确认 datadiv_decode 加密的格式字符串 |
| `sign_verify/bili_sign.py` | 可复用的 sign 计算模块 |
| `sign_verify/sign_from_reverse.py` | 逆向文档 + 验证用例 |

---

> 上一篇：[sign逆向分析实录.md](./sign逆向分析实录.md)
> 相关：[frida_环境搭建与bilibili绕过.md](./frida_环境搭建与bilibili绕过.md) · [bilibili_ssl明文拦截_技术实录.md](./bilibili_ssl明文拦截_技术实录.md)

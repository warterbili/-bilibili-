# B站 sign 签名算法逆向分析实录

> 分析日期：2026-02-19
> 工具：jadx-gui 1.5.4 + Ghidra 12.0.3
> 目标：独立找到 sign 算法的完整调用链，理解逆向方法论

---

## 一、分析目标

从抓包已知 B站评论 API 的请求体包含 `sign` 字段：

```
POST /x/v2/reply/add
access_key=...&appkey=1d8b6e7d45233436&message=...&sign=83f5e24c3e2a92761f06d274ff412fb2
```

目标：不靠网络资料，自己通过逆向手段找到 sign 的生成逻辑和 appSecret 的存储位置。

---

## 二、逆向方法论（核心思想）

### 错误的入口：字符串搜索

新手直觉是直接搜索关键字符串（如 `1d8b6e7d45233436`、`sign`、`appSecret`）。

**为什么失败：**
- jadx 搜索 `1d8b6e7d45233436` → 结果为 0
- Ghidra strings 搜索 `sign`、`MD5` → 结果为 0
- 原因：B站对所有敏感字符串做了 **datadiv_decode 运行时解密**，字符串不以明文存在于二进制中

### 正确的入口：调用链追踪

> 不搜字符串，找「不可能被混淆」的入口点，然后沿调用链向内追踪。

**什么是不可能被混淆的：**
1. **JNI 函数名** — Java 层调用 .so 需要精确匹配，混淆了 App 就崩溃
2. **已知的 API 路径字符串** — URL 路径是网络通信必需的，加密了请求发不出去
3. **框架级方法名** — `addInterceptor`、`intercept` 等

---

## 三、实际分析步骤

### Step 1：jadx 打开 APK，搜索 API 路径

在 jadx 中搜索 `x/v2/reply` 找到 Retrofit 接口定义：

```java
// 文件：BiliCommentApiService（Retrofit 接口）
@FormUrlEncoded
@POST("/x/v2/reply/add")
BiliCall<GeneralResponse<BiliCommentAddResult>> postComment(@FieldMap Map<String, String> map);
```

**关键发现：** `map` 里没有 `sign` 和 `appkey`，说明这两个参数是在更底层被添加的。

---

### Step 2：追 postComment 的调用者

右键 → 查找用例，找到调用处：

```java
// 发评论的业务逻辑类
arrayMap.put("spmid", ...);
arrayMap.put("from_spmid", ...);
arrayMap.put("sync_to_dynamic", ...);
// 注意：这里没有 sign 和 appkey！
return h().postComment(arrayMap);
```

`h()` 方法返回 `BiliCommentApiService`，通过 `ServiceGenerator.createService()` 创建。

---

### Step 3：追 ServiceGenerator

```java
// ServiceGenerator.a() — 构建 OkHttpClient
OkHttpClient.Builder builderNewBuilder = b.a().newBuilder();
builderNewBuilder.interceptors().addAll(sOkClientConfig.interceptors());
builderNewBuilder.networkInterceptors().addAll(sOkClientConfig.networkInterceptors());
```

拦截器来自外部注册，`b.a()` 提供基础 OkHttpClient。

`b.a()` 使用依赖注入（GripperKt）或 fallback 到 `OkHttpClientWrapper.get()`。

---

### Step 4：找到 DefaultRequestInterceptor

通过 import 发现关键类：

```java
import com.bilibili.okretro.interceptor.DefaultRequestInterceptor;
```

进入该类，找到核心逻辑：

```java
// DefaultRequestInterceptor.intercept() — 每个请求都经过这里
@Override
public Request intercept(Request request) {
    Request.Builder builder = request.newBuilder();
    addHeader(builder);           // 加 headers
    if ("POST".equals(request.method())) {
        addCommonParamToBodyResult(...);  // 加公共参数并签名
    }
    return builder.build();
}

// addCommonParam() — 加入所有公共参数
protected void addCommonParam(Map<String, String> map) {
    map.put("platform", "android");
    map.put("mobi_app", BiliConfig.getMobiApp());
    map.put("appkey", getAppKey());          // appkey 在这里加入
    map.put("build", ...);
    map.put("channel", ...);
    map.put("access_key", ...);
    ...
}

// 签名
protected SignedQuery signQuery(Map<String, String> map) {
    return LibBili.signQuery(map);           // 调用 native 层
}
```

**关键发现：** sign 在 `DefaultRequestInterceptor` 的拦截器中统一加入所有请求。

---

### Step 5：追 LibBili.signQuery()

```java
// LibBili.java — JNI 桥接类
public static SignedQuery signQuery(Map<String, String> map) {
    return s(map == null ? new TreeMap() : new TreeMap(map));
    //       ↑ TreeMap 自动按 key 字母序排列！
}

// native 声明
static native SignedQuery s(SortedMap<String, String> sortedMap);

// appKey 也是 native
private static native String a(String str);
public static String getAppKey(String str) { return a(str); }

// 静态初始化块加载 libbili.so
static {
    jp4.c.c(GHttpDnsProvider.SP_BILI);  // 加载 "bili" → libbili.so
}
```

**关键发现：**
1. `s()` 是 native 方法，实现在 `libbili.so`
2. 参数在传入前已经用 `TreeMap` 排序（字母序）
3. `getAppKey()` 也是 native，appkey 和 appSecret 都在 native 层

---

### Step 6：Ghidra 分析 libbili.so

**遇到的障碍：**

1. **OLLVM 控制流平坦化**

   所有函数都被改造成状态机结构：
   ```c
   // 正常代码 5 行，混淆后变成 100+ 行的 while + iVar5/iVar6 状态跳转
   while (iVar5 = iVar6, ...) {
       if (iVar5 == 0x1855e784) { ... }
       else if (iVar5 == 0x189fd33e) { ... }
       ...
   }
   ```

   额外特征：`x.100`、`y.101` 等变量是 **OLLVM 不透明谓词**，始终为 true/false，用于制造假分支迷惑分析。

2. **datadiv_decode 字符串加密**

   所有敏感字符串（appkey、appSecret、类名、方法名）都通过 `.datadiv_decode16350188942804562178` 等函数在运行时解密。Ghidra 静态看到的只有加密后的乱码。

3. **JNI RegisterNatives 动态注册**

   没有 `Java_com_bilibili_*` 形式的导出函数。方法映射在 `JNI_OnLoad` 运行时通过 `RegisterNatives` 动态完成，方法表地址 `PTR_DAT_001d8010`（11 个方法）。

**找到的关键信息：**
- `J4A_FindClass__catchAll` 等 J4A 辅助库函数明文存在 → libbili.so 使用 J4A 动态查找类
- `FUN_00108da0` 是反篡改回调函数（随机延迟 5-15 秒后 exit）

---

## 四、完整调用链（最终结论）

```
【Java 层】
postComment(arrayMap)          ← arrayMap 里无 sign
    ↓
DefaultRequestInterceptor
    ↓ addCommonParam()         ← 加入 platform、appkey、build、channel、access_key 等
    ↓ new TreeMap(map)         ← 按 key 字母序排列
    ↓ LibBili.s(sortedMap)     ← JNI 调用

【Native 层 — libbili.so】
    ↓ RegisterNatives 动态注册的 sign 函数
    ↓ datadiv_decode 解密 appSecret
    ↓ MD5(sorted_params_string + appSecret)
    ↓ 返回 SignedQuery 对象

【结果】
sign = MD5("access_key=...&appkey=...&...&appSecret")
```

---

## 五、遇到的壁垒与解法

| 壁垒 | 原因 | 解法 |
|------|------|------|
| jadx 搜不到 appkey 字符串 | DEX VMP 保护 + 字符串加密 | 改为搜 URL 路径 / 框架方法名 |
| Ghidra strings 找不到敏感字符串 | datadiv_decode 运行时解密 | 静态：模拟执行解密函数；动态：Frida |
| 函数逻辑完全不可读 | OLLVM 控制流平坦化 | 静态：D-810 去混淆插件；动态：Frida Hook |
| 找不到 JNI 导出函数 | RegisterNatives 动态注册 | 分析 JNI_OnLoad 中的方法表 |

---

## 六、学到的逆向技能

1. **jadx 静态分析思路**
   - 不搜字符串值，搜 API 路径、类名、方法名
   - 通过 `查找用例` 追调用链
   - 识别 `import` 中的关键类

2. **识别 JNI 调用模式**
   - Java 层出现 `native` 关键字 → 实现在 .so
   - `static { System.loadLibrary(...) }` → 确定目标 .so

3. **Ghidra 使用基础**
   - Symbol Tree → Exports 查看导出函数
   - Search → For Strings 扫描字符串
   - 双击函数名跨函数跳转

4. **识别工业级保护方案**
   - OLLVM 特征：while + 状态变量 + 不透明谓词（`x.N`、`y.N`）
   - datadiv_decode 特征：大量 `.datadiv_decode数字` 函数名
   - RegisterNatives 动态注册：Exports 里只有 `JNI_OnLoad`，没有 `Java_` 前缀函数

---

## 七、下一步

### 方向 A：静态去混淆（深度学习路线）
1. 为 Ghidra 安装 **D-810 插件** → 还原 OLLVM 控制流
2. 编写 **Ghidra 脚本模拟执行** datadiv_decode → 解密所有字符串
3. 直接在反编译代码中读 sign 算法和 appSecret

### 方向 B：Frida 动态分析（实战路线）
```javascript
// Hook MD5_Update，截获被 hash 的原始字符串
// 字符串末尾去掉已知参数部分，剩余即为 appSecret
var MD5_Update = Module.findExportByName("libcrypto.so", "MD5_Update");
Interceptor.attach(MD5_Update, {
    onEnter: function(args) {
        console.log(Memory.readUtf8String(args[1], args[2].toInt32()));
    }
});
```

### 方向 C：Hook LibBili.s()（最直接）
```javascript
Java.perform(function() {
    var LibBili = Java.use('com.bilibili.nativelibrary.LibBili');
    LibBili.signQuery.overload('java.util.Map').implementation = function(map) {
        var result = this.signQuery(map);
        console.log('SignedQuery:', result.toString());
        return result;
    };
});
```

---

## 八、心得总结

> **逆向不是大海捞针，是系统性地从已知向未知推进。**

1. 从抓包已知的数据（sign 字段）出发
2. 找到不可能被混淆的代码入口（API URL 路径）
3. 沿调用链一层层向内追踪
4. 遇到混淆壁垒时，识别混淆类型，选择对应的破解工具
5. 静态分析和动态分析是互补关系，不是替代关系

B站的保护等级相当高（OLLVM + datadiv_decode + RegisterNatives + DEX VMP），这也是为什么市面上逆向 B站的文章大多依赖动态分析而非纯静态分析。

---

> 上一篇：[bilibili_ssl明文拦截_技术实录.md](./bilibili_ssl明文拦截_技术实录.md)
> 下一篇：[bilibili_sign动态逆向完整实战.md](./bilibili_sign动态逆向完整实战.md)（Frida + Ghidra 联合分析，完整还原算法）

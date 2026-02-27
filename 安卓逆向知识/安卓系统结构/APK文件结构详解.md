# APK 文件结构详解

## 一、APK 是什么

APK（Android Package Kit）本质上是一个 **ZIP 压缩包**，可以直接用解压工具打开。它包含了一个 Android 应用运行所需的全部内容：代码、资源、配置、签名。

```bash
# 验证：直接用 unzip 查看 APK 内容
unzip -l example.apk

# 或者改后缀为 .zip 后用任意解压工具打开
```

---

## 二、APK 整体结构总览

```
example.apk
│
├── AndroidManifest.xml          # 应用清单文件（二进制 XML）
│
├── classes.dex                  # 主 DEX 字节码文件
├── classes2.dex                 # 第二个 DEX（MultiDex）
├── classes3.dex                 # ...可能有更多
│
├── resources.arsc               # 编译后的资源索引表
│
├── res/                         # 编译后的资源文件
│   ├── layout/
│   ├── drawable-*/
│   ├── values/
│   ├── xml/
│   ├── anim/
│   ├── color/
│   ├── menu/
│   ├── mipmap-*/
│   └── raw/
│
├── lib/                         # 原生 .so 共享库
│   ├── armeabi-v7a/
│   ├── arm64-v8a/
│   ├── x86/
│   └── x86_64/
│
├── assets/                      # 原始资源（不经编译处理）
│
├── META-INF/                    # 签名与校验信息
│   ├── MANIFEST.MF
│   ├── CERT.SF
│   └── CERT.RSA (或 .EC/.DSA)
│
├── kotlin/                      # Kotlin 元数据（可选）
├── org/                         # 第三方库附带的文件（可选）
└── okhttp3/                     # 第三方库的配置文件（可选）
```

---

## 三、各文件/目录详细解析

### 3.1 `AndroidManifest.xml` — 应用清单

**重要程度：★★★★★**

这是 APK 中**最重要的文件**，声明了应用的所有核心信息。APK 中的是**二进制 XML 格式**（AXML），无法直接阅读，需要工具解码。

#### 包含信息

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app"           <!-- 包名 -->
    android:versionCode="100"                  <!-- 版本号 -->
    android:versionName="1.0.0">               <!-- 版本名 -->

    <!-- 权限声明 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>

    <!-- SDK 版本要求 -->
    <uses-sdk android:minSdkVersion="21"
              android:targetSdkVersion="33"/>

    <application
        android:name=".MyApplication"          <!-- Application 入口类 -->
        android:debuggable="false"             <!-- ★ 是否可调试 -->
        android:allowBackup="true"             <!-- 是否允许备份 -->
        android:networkSecurityConfig="@xml/network_security_config">

        <!-- 四大组件 -->
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <service android:name=".MyService"/>
        <receiver android:name=".MyReceiver"/>
        <provider android:name=".MyProvider"
                  android:authorities="com.example.app.provider"/>
    </application>
</manifest>
```

#### 逆向关注点

| 字段 | 逆向意义 |
|------|----------|
| `package` | 确定应用包名，定位数据目录 |
| `android:debuggable` | 是否可附加调试器，可修改为 `true` 开启调试 |
| `android:allowBackup` | `true` 时可通过 `adb backup` 导出应用数据 |
| 四大组件 `exported` | 暴露的组件可被外部调用，存在安全风险 |
| `<meta-data>` | 可能包含 API Key、渠道号等敏感信息 |
| `networkSecurityConfig` | 网络安全配置，影响抓包 |

#### 解码工具

```bash
# apktool 解码（推荐，完整反编译）
apktool d example.apk

# aapt2 查看
aapt2 dump xmltree example.apk --file AndroidManifest.xml

# jadx 直接查看
jadx-gui example.apk   # 左侧树可直接浏览 Manifest
```

---

### 3.2 `classes.dex` — Dalvik 字节码

**重要程度：★★★★★**

这是应用的**核心代码**，包含所有 Java/Kotlin 源码编译后的 Dalvik 字节码。

#### DEX 文件格式

```
DEX 文件结构：
┌─────────────────────┐
│     header           │  魔数(dex\n035)、校验和、文件大小等
├─────────────────────┤
│     string_ids       │  所有字符串的索引
├─────────────────────┤
│     type_ids         │  类型（类名、基本类型）索引
├─────────────────────┤
│     proto_ids        │  方法原型（参数+返回值）索引
├─────────────────────┤
│     field_ids        │  字段引用索引
├─────────────────────┤
│     method_ids       │  方法引用索引
├─────────────────────┤
│     class_defs       │  类定义信息
├─────────────────────┤
│     data             │  实际的代码、字符串数据等
├─────────────────────┤
│     link_data        │  链接数据
└─────────────────────┘
```

#### MultiDex

单个 DEX 文件的方法数上限为 **65536**（64K 限制），超过时会拆分为多个 DEX：

```
classes.dex      # 主 DEX
classes2.dex     # 第二个 DEX
classes3.dex     # 第三个 DEX
...              # 大型应用可能有十几个
```

#### 逆向工具链

```bash
# 1. 反编译为 Smali（最忠实还原）
apktool d example.apk          # 输出到 smali/ 目录
baksmali d classes.dex          # 单独反编译 DEX

# 2. 反编译为 Java（可读性最好）
jadx -d output/ example.apk     # 命令行
jadx-gui example.apk            # GUI 界面（推荐）

# 3. DEX → JAR → Java
d2j-dex2jar classes.dex         # 转为 JAR
jd-gui classes-dex2jar.jar      # 用 JD-GUI 查看

# 4. 专业逆向工具
JEB Decompiler                   # 商业工具，效果最好
GDA                              # 国产免费 DEX 分析工具
```

#### Smali 语法速览

Smali 是 DEX 的汇编表示，逆向修改时经常需要编辑：

```smali
# 方法定义
.method public static isVip()Z    # Z = boolean 返回值
    .registers 1

    const/4 v0, 0x0               # v0 = false
    # 修改为 const/4 v0, 0x1     → 永远返回 true（破解VIP）
    return v0
.end method

# 类型缩写
# V=void, Z=boolean, I=int, J=long, F=float, D=double
# L=对象(Lcom/example/MyClass;), [=数组([I = int[])
```

---

### 3.3 `resources.arsc` — 资源索引表

**重要程度：★★★☆☆**

二进制格式的资源映射表，记录了所有资源 ID（`R.`类中的值）到实际资源文件的映射关系。

```
资源ID (0x7f010001) → 资源类型 + 资源名 → 实际文件路径/值
```

包含内容：
- 字符串资源（`strings.xml` 编译后的结果）
- 颜色、尺寸、样式等值类型资源
- 资源 ID 到文件路径的映射

```bash
# 查看资源表
aapt2 dump resources example.apk

# apktool 会自动还原资源
apktool d example.apk
# 还原后在 res/values/ 下可看到 strings.xml 等
```

---

### 3.4 `res/` — 编译后的资源

**重要程度：★★★☆☆**

包含各类资源文件，其中 XML 文件已被编译为**二进制 XML 格式**。

```
res/
├── layout/                      # 界面布局
│   ├── activity_main.xml        # 主界面布局
│   ├── fragment_login.xml       # 登录页面
│   └── item_list.xml            # 列表项布局
│
├── drawable-hdpi/               # 不同分辨率的图片
├── drawable-xhdpi/
├── drawable-xxhdpi/
├── drawable-xxxhdpi/
│
├── mipmap-hdpi/                 # 应用图标（各分辨率）
├── mipmap-xhdpi/
├── mipmap-xxhdpi/
│
├── values/                      # 值资源
│   ├── strings.xml              # 字符串（多语言基础）
│   ├── colors.xml               # 颜色定义
│   ├── dimens.xml               # 尺寸定义
│   ├── styles.xml               # 样式/主题
│   └── attrs.xml                # 自定义属性
│
├── xml/                         # 配置 XML
│   ├── network_security_config.xml  # ★ 网络安全配置
│   ├── file_paths.xml           # FileProvider 路径
│   └── preferences.xml          # 设置页面
│
├── anim/                        # 动画定义
├── animator/                    # 属性动画
├── color/                       # 颜色状态列表
├── menu/                        # 菜单定义
└── raw/                         # 原始文件（不压缩）
```

#### 逆向关注点

- **`xml/network_security_config.xml`**：决定了应用是否信任用户证书，直接影响 HTTPS 抓包。修改此文件可绕过证书固定（Certificate Pinning）的初级防护。
- **`layout/`**：分析界面结构，辅助理解应用逻辑。
- **`values/strings.xml`**：可能包含 URL、密钥等硬编码信息。

---

### 3.5 `lib/` — 原生 SO 库

**重要程度：★★★★☆**

存放 C/C++ 编译的原生共享库，按 CPU 架构分目录：

```
lib/
├── armeabi-v7a/            # 32位 ARM（兼容性最广）
│   ├── libapp.so           # 应用自身的原生库
│   ├── libnative-lib.so    # NDK 编写的业务逻辑
│   └── libssl.so           # OpenSSL 等第三方库
│
├── arm64-v8a/              # 64位 ARM（现代设备主流）
│   ├── libapp.so
│   └── ...
│
├── x86/                    # x86（模拟器常用）
└── x86_64/                 # x86_64
```

#### 架构选择

| 架构 | 适用场景 |
|------|----------|
| `arm64-v8a` | 现代手机（2016年后大多数设备） |
| `armeabi-v7a` | 老设备兼容，32位 ARM |
| `x86` / `x86_64` | Android 模拟器 |

#### 逆向分析

```bash
# 查看 SO 文件信息
file lib/arm64-v8a/libapp.so
readelf -h lib/arm64-v8a/libapp.so

# 查看导出函数
nm -D lib/arm64-v8a/libapp.so

# IDA Pro 分析
# 直接拖入 IDA，选择对应架构

# Ghidra 分析（免费替代 IDA）
ghidraRun   # 导入 SO 文件分析

# Frida Hook SO 中的函数
Interceptor.attach(Module.findExportByName("libapp.so", "Java_com_example_NativeLib_check"), {
    onEnter: function(args) { console.log("called!"); },
    onReturn: function(retval) { retval.replace(1); }
});
```

#### 常见 SO 用途

| SO 文件名 | 常见用途 |
|-----------|----------|
| `libapp.so` | Flutter 应用的核心代码 |
| `libil2cpp.so` | Unity 游戏的 IL2CPP 编译代码 |
| `libjiagu.so` / `libexec.so` | 加固壳的核心库 |
| `libsec.so` / `libsgmain.so` | 安全/签名校验库 |
| `libnative-lib.so` | NDK 编写的业务逻辑 |

---

### 3.6 `assets/` — 原始资源

**重要程度：★★★☆☆**

存放不经 Android 资源编译系统处理的**原始文件**，打包时原样保留。

```
assets/
├── config.json              # 配置文件
├── index.html               # WebView 使用的 H5 页面
├── cert/                    # 内置证书
│   └── server.crt
├── model/                   # AI 模型文件
│   └── detect.tflite
├── fonts/                   # 自定义字体
│   └── custom.ttf
├── lua/                     # 脚本文件
├── db/                      # 预置数据库
│   └── init.db
└── channel.txt              # 渠道标识
```

#### 逆向关注点

- 可能存放**加密的 DEX**（加固壳常用手法，运行时解密加载）
- 内置的**证书文件**（用于 SSL Pinning）
- **配置文件**可能包含服务器地址、密钥等敏感信息
- **H5/RN/Flutter** 等跨平台框架的业务代码可能在此目录

---

### 3.7 `META-INF/` — 签名信息

**重要程度：★★★★☆**

包含 APK 的数字签名，用于验证完整性和来源。

```
META-INF/
├── MANIFEST.MF          # 每个文件的 SHA 摘要
├── CERT.SF              # 对 MANIFEST.MF 各条目的签名
└── CERT.RSA             # 开发者证书和公钥（也可能是 .EC 或 .DSA）
```

#### V1 / V2 / V3 签名方案

| 签名方案 | 位置 | 特点 |
|----------|------|------|
| V1（JAR 签名） | `META-INF/` 目录中 | 传统方案，仅校验 ZIP 条目 |
| V2（APK 签名） | ZIP 中央目录前的签名块 | 校验整个 APK 文件，更安全 |
| V3（APK 签名） | 同 V2 | 增加密钥轮换支持 |
| V4 | 单独的 `.idsig` 文件 | 增量安装优化 |

#### 逆向影响

- **修改 APK 后必须重新签名**，否则无法安装
- V1 签名可在修改后用 `jarsigner` 或 `apksigner` 重签
- V2/V3 签名校验整个文件，需要用 `apksigner` 处理

```bash
# 查看签名信息
apksigner verify --verbose --print-certs example.apk

# 查看证书详情
keytool -printcert -jarfile example.apk

# 重新签名（修改 APK 后必做）
# 1. 生成密钥（仅首次）
keytool -genkey -v -keystore my.keystore -alias mykey \
    -keyalg RSA -keysize 2048 -validity 10000

# 2. 对齐 + 签名
zipalign -v 4 modified.apk aligned.apk
apksigner sign --ks my.keystore --ks-key-alias mykey aligned.apk
```

---

## 四、APK 构建流程（正向理解辅助逆向）

```
Java/Kotlin 源码
       ↓  javac / kotlinc
    .class 文件
       ↓  D8/R8 编译器
    classes.dex
       ↓
资源文件 → aapt2 编译 → resources.arsc + 二进制 XML
       ↓
NDK C/C++ → ndk-build/cmake → lib/*.so
       ↓
    ┌─────────────────┐
    │  APK 打包 (ZIP)  │ ← assets/ 原样复制
    └─────────────────┘
       ↓  zipalign
    对齐优化
       ↓  apksigner
    签名 → 最终 APK
```

> 逆向就是这个流程的**反向操作**：APK → DEX → Smali/Java → 理解/修改逻辑。

---

## 五、常见加固与保护方式

加固会改变 APK 的标准结构，了解这些有助于应对实战：

| 加固类型 | 表现特征 |
|----------|----------|
| DEX 加密 | `classes.dex` 很小，只有壳代码；真正的 DEX 藏在 `assets/` 中加密存放 |
| DEX 抽取 | 方法体被抽空，运行时动态填充 |
| SO 加固 | 关键逻辑移入 `.so`，Java 层只是薄封装 |
| VMP 保护 | 字节码转为自定义虚拟机指令 |
| 资源混淆 | `res/` 下的文件名被混淆（如 `res/a/b.xml`） |
| 字符串加密 | 代码中的字符串被加密，运行时解密 |

#### 识别常见加固厂商

```
# 通过特征文件识别
assets/libjiagu.so          → 360 加固
assets/classes.jar (加密)    → 梆梆加固
lib/libexec.so              → 爱加密
lib/libDexHelper.so         → DEX 加固
lib/libprotectClass.so      → 早期梆梆
assets/libchaosvmp.so       → 数字壳
```

---

## 六、实战：APK 逆向分析流程

```
1. 基本信息采集
   ├── 包名、版本、权限 → aapt2 / jadx 查看 Manifest
   ├── 是否加固 → 查看 lib/ 和 assets/ 特征文件
   └── 签名信息 → apksigner verify

2. 静态分析
   ├── 反编译代码 → jadx / JEB
   ├── 分析入口点 → Application.onCreate → Activity 生命周期
   ├── 搜索关键字符串 → URL、Key、密码、加密函数
   └── 分析 SO 文件 → IDA / Ghidra

3. 动态分析
   ├── 网络抓包 → Charles / mitmproxy（注意证书固定）
   ├── Frida Hook → 拦截关键函数、修改返回值
   ├── 调试运行 → 修改 debuggable + Android Studio / LLDB
   └── 日志分析 → logcat 过滤目标应用

4. 修改与重打包
   ├── apktool 反编译
   ├── 修改 Smali / 资源 / Manifest
   ├── apktool 回编译
   └── 重新签名安装
```

---

## 七、常用工具一览

| 工具 | 用途 | 类型 |
|------|------|------|
| **jadx** | DEX → Java 反编译 | 免费 |
| **apktool** | APK 反编译/回编译 | 免费 |
| **JEB** | 专业 Android 逆向 | 商业 |
| **IDA Pro** | SO 文件反汇编/反编译 | 商业 |
| **Ghidra** | SO 文件分析（NSA 开源） | 免费 |
| **Frida** | 动态 Hook 框架 | 免费 |
| **objection** | 基于 Frida 的自动化工具 | 免费 |
| **dex2jar** | DEX → JAR 转换 | 免费 |
| **baksmali** | DEX → Smali 反汇编 | 免费 |
| **apksigner** | APK 签名工具 | 免费 |
| **Charles** | HTTPS 抓包代理 | 商业 |

---

*文档创建日期：2026-02-22*

# APK 打包流程详解

## 一、总览

APK 的打包是将源码、资源、原生库等原材料经过一系列编译、转换、合并、签名步骤，最终生成一个可安装的 `.apk` 文件。理解正向打包流程，对逆向分析有直接帮助——**逆向就是打包的反向操作**。

```
                          APK 打包全流程
 ┌──────────────────────────────────────────────────────────┐
 │                                                          │
 │  源码(.java/.kt)  资源(res/)  assets/  .so库  AIDL       │
 │       │              │          │        │      │        │
 │       ▼              ▼          │        │      ▼        │
 │    javac/kotlinc   aapt2        │        │    aidl       │
 │       │           compile       │        │      │        │
 │       ▼              │          │        │      ▼        │
 │    .class 文件       ▼          │        │   .java       │
 │       │          aapt2 link     │        │      │        │
 │       │           ┌──┴──┐       │        │      │        │
 │       │           │     │       │        │      ▼        │
 │       │      .arsc   R.java     │        │   javac       │
 │       │                │        │        │      │        │
 │       ◄────────────────┘        │        │      │        │
 │       │                         │        │      │        │
 │       ▼                         │        │      │        │
 │    D8 / R8 编译器               │        │      │        │
 │       │                         │        │      │        │
 │       ▼                         │        │      │        │
 │   classes.dex                   │        │      │        │
 │       │                         │        │      │        │
 │       └──────────┬──────────────┘────────┘      │        │
 │                  ▼                               │        │
 │           APK 打包器（zipflinger）               │        │
 │                  │                               │        │
 │                  ▼                               │        │
 │             未签名 APK                           │        │
 │                  │                               │        │
 │                  ▼                               │        │
 │              zipalign（对齐优化）                 │        │
 │                  │                               │        │
 │                  ▼                               │        │
 │              apksigner（签名）                   │        │
 │                  │                               │        │
 │                  ▼                               │        │
 │             最终可安装 APK                       │        │
 └──────────────────────────────────────────────────────────┘
```

---

## 二、第一步：AIDL 处理

### 什么是 AIDL

AIDL（Android Interface Definition Language）用于定义跨进程通信（IPC）的接口。

```
输入：.aidl 文件
输出：.java 接口文件（包含 Stub 和 Proxy）
工具：aidl 编译器
```

### 示例

```aidl
// IMyService.aidl
interface IMyService {
    String getData(int id);
}
```

编译后生成 `IMyService.java`，包含：
- `IMyService.Stub`（服务端实现的抽象类）
- `IMyService.Stub.Proxy`（客户端使用的代理类）

> **逆向关联**：在反编译代码中看到 `Stub`/`Proxy` 类，就知道这是跨进程通信，可以关注 `transact()` 方法中的数据传递。

---

## 三、第二步：资源编译（aapt2）

资源编译分为两个阶段：**compile** 和 **link**。

### 3.1 aapt2 compile（编译阶段）

将各个资源文件编译为中间二进制格式（`.flat` 文件）。

```bash
# 编译单个资源
aapt2 compile res/layout/activity_main.xml -o compiled/

# 编译整个 res 目录
aapt2 compile --dir res/ -o compiled/
```

```
输入：res/ 下的所有资源文件
      - XML 文件（layout, drawable, values 等）
      - 图片文件（PNG, WebP 等）
      - 其他资源
输出：.flat 中间文件（二进制编译格式）
```

处理细节：
- **XML 文件** → 解析验证 → 编译为二进制 XML 格式
- **PNG 图片** → 可选压缩优化（crunching）
- **values/*.xml** → 解析并提取 string/color/dimen 等值

### 3.2 aapt2 link（链接阶段）

将所有 `.flat` 文件合并，生成最终的资源表和 R 类。

```bash
aapt2 link compiled/*.flat \
    -I android.jar \              # Android 框架资源
    --manifest AndroidManifest.xml \
    -o output.apk \
    --java gen/                   # R.java 输出目录
```

```
输入：所有 .flat 文件 + AndroidManifest.xml + android.jar
输出：
  ├── resources.arsc      # 资源索引表
  ├── R.java              # 资源 ID 常量类
  ├── 二进制 XML 文件      # 编译后的 Manifest 和其他 XML
  └── 初步的 APK 结构
```

### R.java 的作用

```java
// 自动生成的 R.java
public final class R {
    public static final class layout {
        public static final int activity_main = 0x7f030001;
    }
    public static final class string {
        public static final int app_name = 0x7f050001;
        public static final int hello = 0x7f050002;
    }
    public static final class drawable {
        public static final int ic_launcher = 0x7f020001;
    }
}
```

每个资源被分配一个 **32位的资源 ID**：

```
0x 7f 05 0001
   │  │  │
   │  │  └── 资源序号（entry）
   │  └───── 资源类型（type）：01=attr, 02=drawable, 03=layout, 05=string ...
   └──────── 包 ID（package）：7f = 应用本身, 01 = Android 框架
```

> **逆向关联**：在 Smali 中经常看到 `0x7fXXXXXX` 这类常量，就是资源 ID。通过 `resources.arsc` 可反查其对应的资源名和值。

---

## 四、第三步：Java/Kotlin 编译

### 4.1 源码编译为 .class

```
输入：
  ├── 应用源码 (.java / .kt)
  ├── R.java（aapt2 生成）
  ├── AIDL 生成的 .java
  ├── BuildConfig.java（Gradle 生成）
  ├── DataBinding 生成的代码
  └── 注解处理器（APT/KAPT/KSP）生成的代码

编译器：
  ├── javac（Java 编译器）
  └── kotlinc（Kotlin 编译器）

输出：.class 字节码文件
```

### 4.2 注解处理（Annotation Processing）

编译阶段会运行注解处理器，自动生成代码：

| 库 | 注解 | 生成内容 |
|----|------|----------|
| Dagger/Hilt | `@Inject`, `@Component` | 依赖注入工厂类 |
| Room | `@Database`, `@Dao` | 数据库访问实现 |
| Retrofit | `@GET`, `@POST` | 网络请求实现（运行时代理） |
| ButterKnife | `@BindView` | View 绑定代码 |
| Gson/Moshi | `@SerializedName` | JSON 序列化适配器 |

> **逆向关联**：反编译时看到大量 `_Factory`、`_Impl`、`_MembersInjector` 等类名，都是注解处理器自动生成的，了解这一点能避免在这些"胶水代码"上浪费时间。

---

## 五、第四步：DEX 编译（D8 / R8）

这是打包流程中**最关键的一步**，也是逆向分析的核心对象。

### 5.1 D8 编译器

D8 是 Google 官方的 DEX 编译器，将 `.class` 字节码转换为 Dalvik 字节码。

```
输入：
  ├── 应用的 .class 文件
  ├── 第三方库的 .class / .jar / .aar
  └── Android SDK 中的 android.jar（提供 API 定义）

处理过程：
  JVM 字节码 (.class) → 脱糖(Desugar) → Dalvik 字节码 (.dex)

输出：classes.dex, classes2.dex, ...
```

### 5.2 脱糖（Desugaring）

Java 8+ 的高级语法特性在 Android 低版本上不被原生支持，D8 会进行"脱糖"处理：

```java
// 源码中使用 Lambda 表达式（Java 8）
list.forEach(item -> System.out.println(item));

// 脱糖后（等价转换为匿名内部类）
list.forEach(new Consumer<String>() {
    @Override
    public void accept(String item) {
        System.out.println(item);
    }
});
```

其他脱糖处理包括：
- `try-with-resources` → 展开为 `try-finally`
- 接口默认方法 → 生成辅助类
- `Optional`、`Stream` API → 通过 core library desugaring 提供

> **逆向关联**：在反编译代码中看到 `-$$Lambda$XXX` 这样的类名，就是 Lambda 脱糖产物。jadx 通常能将其还原为 Lambda 表达式。

### 5.3 R8（优化 + 混淆 + 缩减）

R8 是 D8 的升级版，在 Release 构建中使用，额外做了三件事：

```
┌──────────────────────────────────────────────┐
│                   R8 三大功能                  │
├──────────────────────────────────────────────┤
│                                              │
│  1. Tree Shaking（代码缩减）                  │
│     移除未被引用的类、方法、字段               │
│     大幅缩小 APK 体积                         │
│                                              │
│  2. Optimization（代码优化）                  │
│     内联短方法、消除死代码                     │
│     优化控制流、合并常量                       │
│                                              │
│  3. Obfuscation（代码混淆）                   │
│     类名/方法名/字段名 → a, b, c ...          │
│     依据 proguard-rules.pro 配置              │
│                                              │
└──────────────────────────────────────────────┘
```

#### proguard-rules.pro 配置示例

```proguard
# 保留入口点
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service

# 保留序列化相关
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
}

# 保留 JNI 方法名（SO 调用需要）
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留枚举
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
```

#### 混淆效果对比

```java
// 混淆前
public class UserManager {
    private String accessToken;
    public boolean isLoggedIn() { ... }
    public void logout() { ... }
}

// 混淆后
public class a {
    private String b;
    public boolean a() { ... }
    public void c() { ... }
}
```

> **逆向关联**：
> - 混淆是逆向的第一道障碍。`mapping.txt` 文件记录了混淆映射，如果能拿到就可以完整还原。
> - R8 的 Tree Shaking 意味着最终 APK 中不包含未使用的代码，所以你在 APK 中看到的都是实际运行的。
> - 注意 `-keep` 规则保留的类名不会被混淆，这些通常是关键入口点。

### 5.4 MultiDex 分包

单个 DEX 方法数上限 65536，超过后自动拆分：

```
                  所有 .class 文件
                       │
                       ▼
              ┌── 按依赖关系分析 ──┐
              │                    │
              ▼                    ▼
        classes.dex          classes2.dex
     (主 DEX，包含           (次 DEX，包含
      启动必需的类)            其余类)
              │                    │
              ▼                    ▼
        启动时直接加载        运行时按需加载
```

主 DEX 必须包含：
- `Application` 类
- 启动所需的 `Activity`
- 引用到的所有直接依赖类
- `MultiDexApplication` 相关类

---

## 六、第五步：打包合并

将所有产物合并成一个 APK（ZIP）文件。

```
打包输入：
├── classes.dex, classes2.dex ...   （D8/R8 产出）
├── resources.arsc                   （aapt2 产出）
├── 编译后的 AndroidManifest.xml     （aapt2 产出）
├── res/ 下的二进制资源               （aapt2 产出）
├── lib/**/*.so                      （NDK/CMake 产出）
├── assets/*                         （原样复制）
└── 其他文件                          （kotlin/, META-INF 等）

工具：zipflinger / Android Gradle Plugin 内置打包器

输出：未签名的 APK 文件
```

打包过程本质上就是创建一个 ZIP 文件，按照 APK 的目录规范将各文件放入正确位置。

---

## 七、第六步：对齐优化（zipalign）

### 什么是 zipalign

zipalign 确保 APK 内所有未压缩的数据都从文件起始位置的 **4 字节边界** 开始对齐。

```bash
# 对齐处理
zipalign -v 4 unaligned.apk aligned.apk

# 验证是否已对齐
zipalign -c -v 4 aligned.apk
```

### 为什么需要对齐

```
未对齐：
┌──────┬──┬────────────┬───┬──────────┐
│header│XX│  文件内容   │XXX│ 文件内容  │
└──────┴──┴────────────┴───┴──────────┘
           ↑ 偏移量不规则，需要额外计算

对齐后（4字节边界）：
┌──────┬────┬────────────┬────┬──────────┐
│header│pad │  文件内容   │pad │ 文件内容  │
└──────┴────┴────────────┴────┴──────────┘
        ↑ 补齐填充       ↑ 补齐填充
           偏移量是4的倍数，可以直接 mmap 访问
```

优势：
- 系统可以用 `mmap()` 直接映射文件，无需拷贝到内存
- 减少运行时内存占用
- 加快资源访问速度

> **注意**：使用 V2+ 签名方案时，必须**先 zipalign 再签名**，因为签名校验覆盖整个文件内容。

---

## 八、第七步：签名（apksigner）

### 签名的目的

1. **身份验证**：证明 APK 来自特定开发者
2. **完整性保护**：确保 APK 未被篡改
3. **升级校验**：系统只允许相同签名的 APK 进行升级覆盖安装

### V1 签名（JAR 签名）

```
签名过程：
1. 计算每个文件的 SHA 摘要 → MANIFEST.MF
2. 对 MANIFEST.MF 的每个条目签名 → CERT.SF
3. 用私钥对 CERT.SF 签名 → CERT.RSA

验证过程：
APK 内每个文件 → 计算摘要 → 比对 MANIFEST.MF → 验证 CERT.SF 签名
```

```
META-INF/
├── MANIFEST.MF          # 文件摘要清单
│   Name: classes.dex
│   SHA-256-Digest: xxxxxxxxxxxx
│
│   Name: res/layout/activity_main.xml
│   SHA-256-Digest: xxxxxxxxxxxx
│
├── CERT.SF              # 对 MANIFEST.MF 条目的签名
│   SHA-256-Digest-Manifest: xxxxxxxxxxxx
│
│   Name: classes.dex
│   SHA-256-Digest: xxxxxxxxxxxx
│
└── CERT.RSA             # 开发者证书 + 对 CERT.SF 的数字签名
    (二进制 PKCS#7 格式)
```

**V1 缺陷**：只校验 ZIP 条目内容，不校验 ZIP 元数据（中央目录、注释等），存在 Janus 漏洞（CVE-2017-13156）。

### V2 签名（APK 签名方案 v2）

从 Android 7.0 引入，签名覆盖整个 APK 文件：

```
APK 文件结构（ZIP 格式）：
┌─────────────────────┐
│   ZIP 条目内容       │  ← 第1块
│   (文件数据)         │
├─────────────────────┤
│   APK 签名块         │  ← V2 签名插入在此处
│   (APK Signing Block)│
├─────────────────────┤
│   中央目录           │  ← 第2块
│   (Central Directory)│
├─────────────────────┤
│   中央目录结尾        │  ← 第3块
│   (EOCD)             │
└─────────────────────┘

V2 签名校验范围：第1块 + 第2块 + 第3块（除签名块本身外的所有内容）
```

**V2 优势**：
- 校验整个文件，无法在不破坏签名的情况下修改任何内容
- 验证速度更快（不需要解压逐个文件校验）
- 修复了 V1 的 Janus 漏洞

### V3 签名

Android 9.0 引入，在 V2 基础上增加了**密钥轮换**支持：

```
V3 签名块中包含：
├── 当前签名密钥
└── proof-of-rotation 结构
    ├── 旧密钥 A → 签名认证 → 新密钥 B
    └── 旧密钥 B → 签名认证 → 新密钥 C
    （形成信任链，允许更换签名密钥）
```

### 签名实操命令

```bash
# === 生成签名密钥 ===
keytool -genkeypair \
    -keystore release.keystore \
    -alias myapp \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -storepass password123 \
    -keypass password123

# === 完整签名流程 ===

# 1. 对齐（必须在 V2 签名之前）
zipalign -v 4 app-unsigned.apk app-aligned.apk

# 2. 签名（同时使用 V1 + V2 + V3）
apksigner sign \
    --ks release.keystore \
    --ks-key-alias myapp \
    --ks-pass pass:password123 \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    app-aligned.apk

# 3. 验证签名
apksigner verify --verbose --print-certs app-aligned.apk
```

---

## 九、Gradle 构建系统中的实际流程

实际项目中，以上步骤由 **Gradle + Android Gradle Plugin (AGP)** 自动编排：

```
./gradlew assembleRelease 触发的任务链：

:app:preBuild                        # 预检查
:app:generateReleaseBuildConfig       # 生成 BuildConfig.java
:app:javaPreCompileRelease            # 注解处理准备
:app:compileReleaseAidl               # ★ AIDL 编译
:app:compileReleaseRenderscript       # RenderScript 编译
:app:generateReleaseResValues         # 生成资源值
:app:generateReleaseResources         # 资源生成
:app:mergeReleaseResources            # ★ 合并所有模块的资源
:app:processReleaseManifest           # ★ 合并 Manifest
:app:processReleaseResources          # ★ aapt2 compile + link
:app:compileReleaseKotlin             # ★ Kotlin 编译
:app:compileReleaseJavaWithJavac      # ★ Java 编译
:app:mergeReleaseGeneratedProguardFiles  # 合并混淆规则
:app:minifyReleaseWithR8              # ★ R8 (混淆+优化+缩减+DEX)
:app:mergeReleaseNativeLibs           # ★ 合并 .so 库
:app:mergeReleaseJavaResource         # 合并 Java 资源
:app:packageRelease                   # ★ 打包为 APK
:app:createReleaseApkListingFileRedirect
:app:assembleRelease                  # 完成
```

### Debug vs Release 的区别

| 环节 | Debug | Release |
|------|-------|---------|
| 编译器 | D8（无优化） | R8（混淆+优化+缩减） |
| 签名 | 自动使用 debug.keystore | 使用自定义 release.keystore |
| debuggable | `true` | `false` |
| 日志 | 保留 | 通常通过 ProGuard 移除 |
| 优化 | 无 | 代码优化、资源缩减 |

```groovy
// build.gradle 中的配置
android {
    buildTypes {
        debug {
            debuggable true
            minifyEnabled false     // 不混淆
        }
        release {
            debuggable false
            minifyEnabled true      // 启用 R8
            shrinkResources true    // 资源缩减
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
            signingConfig signingConfigs.release
        }
    }
}
```

---

## 十、AAB 与 APK 的关系

从 2021 年起，Google Play 要求上传 **AAB**（Android App Bundle）而非 APK：

```
AAB 打包流程：

开发者端：
  源码 → 编译 → .aab 文件（包含所有架构/语言/分辨率的资源）
                    │
                    ▼ 上传到 Google Play
Google Play 服务端：
  .aab → bundletool → 针对每个设备生成优化的 APK
                    │
                    ▼
  设备A (arm64, xxhdpi, 中文)  → 只包含 arm64 so + xxhdpi 图片 + 中文字符串
  设备B (arm32, hdpi, 英文)    → 只包含 arm32 so + hdpi 图片 + 英文字符串
```

```
AAB 内部结构：
example.aab
├── base/                    # 基础模块
│   ├── manifest/
│   │   └── AndroidManifest.xml
│   ├── dex/
│   │   ├── classes.dex
│   │   └── classes2.dex
│   ├── res/
│   ├── assets/
│   ├── lib/
│   │   ├── arm64-v8a/
│   │   └── armeabi-v7a/
│   ├── root/
│   └── resources.pb         # 资源表（protobuf 格式，非 arsc）
├── feature1/                # 动态功能模块（可选）
├── BundleConfig.pb          # 打包配置
└── BUNDLE-METADATA/
```

> **逆向关联**：从 Google Play 下载的应用实际上是 Split APK（拆分 APK），用 `adb shell pm path <pkg>` 可以看到多个 APK 文件。提取时需要全部拉取。

---

## 十一、逆向视角：反向操作对照表

| 正向步骤 | 逆向操作 | 工具 |
|----------|----------|------|
| Java/Kotlin → .class | .class → Java 源码 | JD-GUI, CFR, Procyon |
| .class → DEX | DEX → .class (JAR) | dex2jar |
| .class → DEX | DEX → Smali | baksmali, apktool |
| .class → DEX | DEX → Java | jadx, JEB |
| R8 混淆 | 反混淆还原 | mapping.txt, jadx 重命名 |
| aapt2 编译资源 | 反编译资源 | apktool |
| 二进制 Manifest | 文本 Manifest | apktool, axmlprinter |
| NDK → .so | .so → 汇编/伪代码 | IDA Pro, Ghidra |
| 签名 | 去签名/重签名 | apksigner, uber-apk-signer |
| zipalign 对齐 | 重对齐 | zipalign |

### 完整逆向重打包流程

```bash
# 1. 反编译
apktool d target.apk -o target_src/

# 2. 修改（Smali 代码、资源、Manifest 等）
#    编辑 target_src/ 下的文件

# 3. 回编译
apktool b target_src/ -o modified.apk

# 4. 对齐
zipalign -v 4 modified.apk aligned.apk

# 5. 重签名
apksigner sign --ks my.keystore --ks-key-alias mykey aligned.apk

# 6. 安装
adb install aligned.apk
```

---

*文档创建日期：2026-02-22*

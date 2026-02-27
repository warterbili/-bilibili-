# 手机自动化与群控方案

## 一、群控方案分类

### 1. 商业群控软件（闭源）
- 群控宝、云控系统等，手机端装 Agent APK，PC端统一下发指令
- 原理：通过无障碍服务（AccessibilityService）或 Root 权限执行操作

### 2. 开源方案
- **Appium** — 基于 WebDriver 协议的自动化框架
- **STF (Smartphone Test Farm)** — OpenSTF，开源多设备管理平台
- **scrcpy + 脚本** — 投屏 + adb 命令批量控制

### 3. 底层原理
- ADB 指令
- Android AccessibilityService（无障碍服务，系统内置 API，无需下载）
- Root + 注入（如 Xposed/Frida）

---

## 二、自动化方案对比

| 方案 | 难度 | 需要Root | 类比 | 适合场景 |
|------|------|---------|------|---------|
| ADB input | 低 | 否 | 坐标硬编码 | 简单脚本 |
| **UIAutomator2** | **低** | **否** | **Playwright** | **自动化入门推荐** |
| Appium | 中 | 否 | Selenium | 专业测试 |
| AutoX.js | 低 | 否 | 油猴脚本 | 手机端自动化 |
| Frida | 高 | 是 | 调试器 | 逆向分析 |

---

## 三、ADB 原生自动化命令

```bash
# 模拟点击坐标 (x, y)
adb shell input tap 500 1000

# 模拟滑动
adb shell input swipe 500 1000 500 300

# 模拟输入文字
adb shell input text "hello"

# 模拟按键（返回键）
adb shell input keyevent BACK

# 截图
adb shell screencap /sdcard/screen.png
```

---

## 四、UIAutomator2（Python，推荐入门）

最像 Playwright 的手机自动化方案，通过 ADB 从电脑端控制手机。

```bash
pip install uiautomator2
```

```python
import uiautomator2 as u2

d = u2.connect()  # 连接手机
d.app_start("com.example.app")  # 启动App

# 用选择器操作，类似 Playwright
d(text="登录").click()
d(resourceId="com.example:id/username").set_text("admin")
d(className="android.widget.Button").click()

# 截图
d.screenshot("screen.png")
```

---

## 五、Appium（业界标准）

跨平台（Android + iOS），支持多语言（Python/Java/JS）。

```python
from appium import webdriver

driver = webdriver.Remote('http://localhost:4723', caps)
driver.find_element(By.ID, "com.example:id/btn").click()
```

---

## 六、AutoX.js（手机端脚本，原AutoJS开源版）

直接在手机上运行 JavaScript 脚本，基于无障碍服务，不需要 Root。

### 官方地址
- GitHub：https://github.com/kkevsekk1/AutoX
- 下载页：https://github.com/kkevsekk1/AutoX/releases
- 下载 **app-v7-universal-release-signed.apk**

### 安装
```bash
adb install "apk文件路径"
```

### 权限配置
1. **设置 → Accessibility（无障碍）** → 找到 AutoX.js → 开启
2. **设置 → Apps** → AutoX.js → 允许悬浮窗权限

---

## 七、Frida（高级逆向工具）

动态注入框架，可以 Hook 任意函数，直接修改 App 逻辑。

- 官网：https://frida.re/
- 需要 Root 权限
- 不只是 UI 自动化，是逆向分析的核心工具

---

> **待办：** 下次深入探讨具体方案的实操使用。

---

## 八、视觉识别自动化方案

当 App 使用自定义渲染（游戏、Canvas 绘制），无障碍服务读不到控件时，需要用**截图 + 图像识别 + 模拟操作**的方案。

### 1. 适用场景

- 游戏自动化（如部落冲突、皇室战争等 OpenGL/Canvas 渲染的游戏）
- 自定义 View 较多的 App（无障碍拿不到控件信息）
- 跨平台通用方案（不依赖 Android 控件树）

### 2. 技术栈

```
截图（adb screencap / scrcpy 帧捕获）
    ↓
图像识别（OpenCV 模板匹配 / YOLO 目标检测 / OCR 文字识别）
    ↓
决策逻辑（Python 脚本）
    ↓
模拟操作（adb input tap/swipe）
```

### 3. 常用工具

| 工具 | 用途 | 说明 |
|------|------|------|
| **OpenCV** | 模板匹配 | 在截图中找到目标图片的位置，简单可靠 |
| **YOLO** | 目标检测 | 训练模型识别游戏中的建筑/兵种等，适合复杂场景 |
| **Tesseract / PaddleOCR** | OCR 文字识别 | 识别屏幕上的数字、文字（如资源数量） |
| **PyAutoGUI** | 电脑端模拟操作 | 配合模拟器使用 |

### 4. 基本示例（OpenCV 模板匹配 + ADB）

```python
import cv2
import subprocess

# 1. 截图
subprocess.run(["adb", "shell", "screencap", "-p", "/sdcard/screen.png"])
subprocess.run(["adb", "pull", "/sdcard/screen.png", "screen.png"])

# 2. 模板匹配：在截图中找目标按钮
screen = cv2.imread("screen.png")
template = cv2.imread("target_button.png")  # 预先截好的按钮图片
result = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
_, max_val, _, max_loc = cv2.minMaxLoc(result)

if max_val > 0.8:  # 相似度阈值
    # 3. 计算按钮中心坐标
    h, w = template.shape[:2]
    cx = max_loc[0] + w // 2
    cy = max_loc[1] + h // 2
    # 4. 点击
    subprocess.run(["adb", "shell", "input", "tap", str(cx), str(cy)])
```

### 5. 与无障碍方案对比

| | 无障碍方案（UIAutomator2/AutoX.js） | 视觉识别方案 |
|---|---|---|
| 原理 | 读取控件树 | 截图 + 图像匹配 |
| 游戏支持 | ❌ 读不到游戏画面控件 | ✅ 只要能截图就行 |
| 速度 | 快 | 慢（截图+识别有延迟） |
| 准确性 | 精确（控件 ID） | 依赖图片质量和阈值 |
| 分辨率适配 | 自动 | 需要处理不同分辨率 |
| 适合 | 普通 App 自动化 | 游戏、自定义渲染 App |

### 6. 注意事项

- **分辨率适配**：不同手机分辨率不同，坐标需要按比例换算
- **反检测**：操作间隔加随机延迟，避免太规律被检测
- **性能**：`adb screencap` 较慢（约 1-2 秒/帧），高频操作可用 scrcpy 帧捕获
- **游戏反作弊**：部分游戏检测模拟点击，有封号风险

### 7. Airtest（网易出品，视觉自动化首选）

**最主流的视觉识别自动化框架**，网易开发并开源，Google 官方推荐。

- GitHub：https://github.com/AirtestProject/Airtest
- 官网：https://airtest.netease.com/
- 专为**游戏自动化**设计，截图匹配开箱即用

#### 全家桶组件

| 组件 | 作用 |
|------|------|
| **Airtest** | 图像识别框架，截图匹配 + 模拟操作（底层用 OpenCV） |
| **Poco** | 控件识别框架，支持 Unity/Cocos2dx 游戏引擎内部控件树 |
| **AirtestIDE** | 可视化编辑器，截图拖拽写脚本，门槛极低 |

#### 安装

```bash
pip install airtest
# 或者直接下载 AirtestIDE（自带一切环境）
```

#### 基本用法

```python
from airtest.core.api import *

# 连接手机
connect_device("Android:///")

# 截图匹配 + 点击（传入目标按钮的截图文件）
touch(Template("attack_button.png"))

# 滑动
swipe(Template("start.png"), Template("end.png"))

# 等待某个画面出现
wait(Template("loading_done.png"), timeout=30)

# 判断画面是否存在
if exists(Template("reward.png")):
    touch(Template("claim.png"))

# 截图保存
snapshot("result.png")
```

#### Poco 用法（游戏引擎控件识别）

```python
from poco.drivers.unity3d import UnityPoco

poco = UnityPoco()

# 直接通过游戏内控件名操作（比图像识别更精确）
poco("btn_attack").click()
poco("input_name").set_text("hello")
poco("scroll_view").swipe("up")
```

#### 视觉自动化方案对比

| 方案 | 特点 | 适合 |
|------|------|------|
| **Airtest** | 开箱即用，有 IDE，最成熟 | **首选，游戏/通用** |
| OpenCV 自己写 | 灵活但要自己造轮子 | 高度定制需求 |
| YOLO + 自定义 | AI 目标检测，最强但门槛高 | 复杂识别（阵型分析等） |

> Airtest 就是视觉自动化领域的 "Playwright"，建议从它开始入门。

---

## 九、APK 安装与签名

### 自写 APK 能否通过 ADB 安装？

可以，但 APK **必须经过签名**才能安装。

- **所有 APK 都必须签名** — Android 系统强制要求，未签名无法安装
- **Debug 签名即可** — Android Studio 自动用 debug keystore 签名，不需要官方证书
- **自签名就行** — 不需要任何机构颁发的证书
- 同一个 APP 更新时签名必须一致，否则需先卸载旧版本
- `adb install` 不受「未知来源」限制，直接点击 APK 安装才需要开启

```bash
# 直接安装
adb install your_app.apk

# 覆盖安装
adb install -r your_app.apk
```

手动签名（不用 Android Studio 时）：
```bash
# 生成密钥
keytool -genkey -v -keystore my-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias mykey

# 签名 APK
apksigner sign --ks my-key.jks your_app.apk
```

### 允许安装未知来源应用（PixelExperience）

路径：**设置 → 安全 → 更多安全设置 → 安装未知应用**

选择安装来源（如文件管理器、Shell），打开「允许来自此来源」开关。

---

## 九、Magisk（面具）功能概览

Root 只是基础，Magisk 的核心价值在于 **模块系统** 和 **隐藏机制**。

### 1. Magisk 模块（systemless，不动 /system 分区）

| 模块 | 作用 |
|------|------|
| **LSPosed** | Xposed 继任者，hook 任意 App 的 Java 方法，逆向必备 |
| **Shamiko** | 隐藏 Root 状态，绕过 Root 检测 |
| **Busybox** | 补全 Linux 命令行工具 |

### 2. Zygisk
内置注入框架，在 Zygote 进程中加载代码，可注入任意 App 进程。

### 3. DenyList（隐藏 Root）
让指定 App 检测不到 Root：银行/支付 App、游戏反作弊、SafetyNet / Play Integrity。

### 4. 对逆向的价值

| 用途 | 说明 |
|------|------|
| LSPosed + 算法助手 | Hook 加密函数，直接看明文 |
| LSPosed + JustTrustMe | 绕过 SSL Pinning，方便抓包 |
| Root + Frida | 动态插桩分析 |
| Root + 文件访问 | 读取 App 私有目录 `/data/data/` |

> **Magisk + LSPosed** 是安卓逆向的核心工具链。

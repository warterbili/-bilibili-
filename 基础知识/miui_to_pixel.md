# 将 MIUI 系统刷成 PixelExperience 系统

## 一、为什么要刷 Pixel 系统

国内手机系统（如 MIUI）存在诸多限制：
- 大量操作依赖厂商账号（如小米账号），增加不必要的束缚
- 对 Root 等高级操作限制较多
- 系统臃肿，内置大量不可卸载的应用

刷入 PixelExperience（Pixel 原生系统）的优势：
- 纯净的 Android 原生体验，无厂商限制
- 更自由地进行 Root、模块安装等操作
- 系统轻量，流畅度更高

## 二、刷机教程

### 参考资料
- 教学视频：https://www.bilibili.com/video/BV13c411R7gq/
- PixelExperience 刷机包下载：https://get.pixelexperience.org/
- Android SDK Platform Tools（adb/fastboot）：https://developer.android.google.cn/tools/releases/platform-tools?hl=zh-cn
- PixelExperience 官方刷机文档（小米9/cepheus）：https://wiki.pixelexperience.org/devices/cepheus/install/

### 准备工作

1. 从 PixelExperience 官网下载对应机型（cepheus）的刷机包（.zip 和 .img）
2. 下载并解压 Android SDK Platform Tools（获取 adb 和 fastboot 命令）
3. 结合视频教程和官方文档，按步骤执行刷机

### 刷机步骤

#### 步骤一：刷入 Recovery

前提：BL 锁已解开，手机进入 Fastboot 模式。

**注意：** 官方文档使用的命令是：
```bash
fastboot flash recovery <recovery_filename>.img
```
但这种方式刷入的 Recovery 容易在重启时被原生 MIUI 系统覆盖，导致进入的仍然是 MIUI Recovery。

**正确做法：** 使用 `fastboot boot` 直接临时启动 Recovery，绕过系统覆盖问题：
```bash
fastboot boot "C:\Users\admin\AppData\小米刷机包2\PixelExperience_Plus_cepheus-13.0-20221127-0343-OFFICIAL.img"
```
这样会直接启动进入 PixelExperience Recovery，而不经过 MIUI 系统。

#### 步骤二：格式化数据

进入 PixelExperience Recovery 后，执行 **Factory Reset / Format data**，清除原有系统数据。

#### 步骤三：Sideload 刷入刷机包

在 Recovery 中选择 **Apply update → Apply from ADB**，然后在电脑上执行：
```bash
adb sideload "C:\Users\admin\AppData\小米刷机包\PixelExperience_Plus_cepheus-13.0-20221127-0343-OFFICIAL.zip"
```
等待传输完成（显示 `Total xfer: 0.98x`），刷机即完成。

#### 步骤四：重启

刷机完成后，在 Recovery 中选择 **Reboot system now**，重启即可进入 PixelExperience 系统。

> **提示：** 整个刷机过程务必结合视频教程和官方文档同步操作，确保每一步都正确执行。

#### 步骤五：开启开发者模式和 USB 调试

1. 进入 **设置 → 关于手机**
2. 拉到最底部，连续点击 **版本号** 7次，开启开发者模式
3. 返回 **设置 → 系统 → 开发者选项**
4. 开启 **USB 调试**

至此，刷机全部完成，手机已可通过 adb 与电脑通信。

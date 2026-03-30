# 通过 ADB 安装安卓应用与工具配置

## 一、ADB 安装应用

通过电脑使用 ADB 将 APK 安装到手机：
```bash
adb install "apk文件路径"
```
显示 `Success` 即安装成功。

## 二、v2rayNG（安卓代理工具）

### 简介
v2rayNG 是 v2ray 的安卓客户端，用于科学上网。

### 官方地址
- v2ray 核心项目：https://github.com/v2fly/v2ray-core
- v2rayNG 安卓客户端：https://github.com/2dust/v2rayNG
- 下载页：https://github.com/2dust/v2rayNG/releases

### 下载与安装
- 小米9 (arm64 架构) 选择 **arm64-v8a** 版本的 APK
- 安装包路径：`C:\Users\admin\AppData\安卓v2ray\v2rayNG_2.0.0_arm64-v8a.apk`
```bash
adb install "C:\Users\admin\AppData\安卓v2ray\v2rayNG_2.0.0_arm64-v8a.apk"
```

## 三、Magisk（面具 / Root 工具）

### 简介
Magisk 是安卓 Root 工具，可以获取超级用户权限、安装模块、隐藏 Root 等。

### 官方地址
- GitHub：https://github.com/topjohnwu/Magisk
- 下载页：https://github.com/topjohnwu/Magisk/releases

### 下载与安装
- 下载 **Magisk-vXX.X.apk**（不要选 app-debug.apk）
- 安装包路径：`C:\Users\admin\AppData\magisk面具\Magisk-v30.6.apk`
```bash
adb install "C:\Users\admin\AppData\magisk面具\Magisk-v30.6.apk"
```

### 获取 Root 权限（修补 boot 镜像）

安装 Magisk APK 只是第一步，还需修补 boot 镜像才能获得 root 权限：

**1. 将 boot.img 传到手机**
从 PixelExperience 刷机包中解压出 `boot.img`：
```bash
adb push "C:\Users\admin\AppData\小米刷机包\PixelExperience_Plus_cepheus-13.0-20221127-0343-OFFICIAL\boot.img" /sdcard/Download/
```

**2. 手机上修补**
- 打开 Magisk App → 安装 → 选择并修补一个文件
- 选择 `Download` 文件夹里的 `boot.img`
- 等待显示 `All done`

**3. 查看修补后的文件名**
```bash
adb shell ls /sdcard/Download/magisk_patched*
```

**4. 传回电脑**
```bash
adb pull /sdcard/Download/magisk_patched-xxxxx.img "C:\Users\admin\AppData\小米刷机包\"
```

**5. 刷入修补后的 boot 镜像**
手机进入 fastboot 模式（关机后长按 **音量下 + 电源键**）：
```bash
fastboot flash boot "修补后的img文件路径"
fastboot reboot
```

**6. 验证 Root**
重启后打开 Magisk App 确认版本号显示正常，然后测试：
```bash
adb shell su -c "whoami"
```
返回 `root` 即成功。手机上弹出 Magisk 授权弹窗时记得点**允许**。

## 四、scrcpy（安卓投屏工具）

### 简介
scrcpy 是安装在**电脑上**的投屏工具，通过 ADB 连接手机，将手机画面投屏到电脑，并可用鼠标键盘操作手机。手机端无需安装任何东西。

### 官方地址
- GitHub：https://github.com/Genymobile/scrcpy
- 下载页：https://github.com/Genymobile/scrcpy/releases

### 下载与配置
- Windows 下载 **scrcpy-win64** 版本的 zip
- 解压路径：`C:\Users\admin\AppData\安卓投屏\scrcpy-win64-v3.3.4\scrcpy-win64-v3.3.4`
- 将该路径添加到系统 **PATH** 环境变量
- 重新打开终端后直接输入 `scrcpy` 即可启动投屏

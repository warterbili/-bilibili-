# ADB 常用指令

## 官方文档

- ADB 官方指令文档：https://developer.android.com/tools/adb?hl=zh-cn#notlisted

## 补充学习资源

- PowerShell 管道与语法：https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/04-pipelines
- Linux Shell 教程（中文）：https://www.runoob.com/linux/linux-shell.html

> `|` `>` `&&` 等符号属于 Shell 语法，不属于 adb 或任何命令，需查 Shell 文档。

---

## 遇到不认识的指令怎么查

```bash
# 查看 adb 自身所有命令
adb help

# 查看 Android 专有工具的帮助
adb shell pm help              # 包管理器
adb shell am help              # 活动管理器
adb shell dumpsys --help       # 系统服务信息

# 查看 shell 中可用的所有 Linux 命令（由 toybox 提供）
adb shell toybox

# 查看某个 Linux 命令的用法
adb shell toybox <命令名> --help
# 例如：
adb shell toybox chmod --help
adb shell toybox ls --help
```

### 命令来源分类

| 来源 | 示例 | 查帮助方式 |
|------|------|-----------|
| adb 自身命令 | push, pull, install | `adb help` |
| Android 专有工具 | pm, am, dumpsys | `adb shell pm help` |
| Linux 基础命令（toybox） | ls, chmod, cat, grep | `adb shell toybox 命令 --help` |
| Magisk（第三方） | su | `adb shell su --help` |

---

## adb push — 推送文件到手机

将本地文件复制到手机上（不会安装，只是传文件）。

```bash
adb push <本地路径> <手机路径>
```

### 示例

```bash
# 推送文件到临时目录
adb push frida-server /data/local/tmp/

# 推送整个文件夹
adb push C:\scripts\ /sdcard/scripts/
```

### 指定设备

连接多台设备时用 `-s` 指定：

```bash
adb devices                          # 先查看设备列表
adb -s <设备序列号> push file /data/local/tmp/
```

### 常用目标路径

| 路径 | 用途 |
|------|------|
| `/data/local/tmp/` | 放工具（frida-server 等），需 root 执行 |
| `/sdcard/` | 放普通文件，App 可访问 |
| `/sdcard/Download/` | 下载目录 |

### 注意事项

- 推送后可能需要加执行权限：`adb shell chmod +x /data/local/tmp/frida-server`
- 路径用正斜杠 `/`

---

## adb pull — 从手机拉取文件到电脑

将手机上的文件复制到本地电脑。

```bash
adb pull <手机路径> <本地路径>
```

### 示例

```bash
# 拉取文件到当前目录
adb pull /sdcard/Download/test.apk .

# 拉取文件到指定目录
adb pull /sdcard/DCIM/photo.jpg C:\Users\admin\Desktop\

# 拉取整个文件夹
adb pull /sdcard/Download/ C:\Users\admin\Desktop\download_backup\

# 拉取 App 私有数据（需要 root）
adb shell su -c "cp /data/data/com.example.app/databases/data.db /sdcard/"
adb pull /sdcard/data.db .
```

### 常用参数

| 参数 | 说明 |
|------|------|
| `-a` | 保留文件时间戳和权限 |
| `-z` | 启用压缩传输（可选算法：brotli/lz4/zstd） |

### 注意事项

- `/data/data/` 下的文件 shell 用户无权直接 pull，需要先 `su -c "cp"` 到 `/sdcard/` 再 pull
- 本地路径写 `.` 表示当前终端所在目录

---

## 提取手机上已安装的 APK 到电脑

用于将手机上的 App 拉到 PC 端进行逆向分析。

### 步骤

```bash
# 1. 查找包名（如果不知道的话）
adb shell pm list packages                    # 列出所有包名
adb shell pm list packages | grep 关键词       # 模糊搜索

# 2. 查询 APK 安装路径
adb shell pm path <包名>
# 输出示例: package:/data/app/~~abc123/com.example.app-xyz/base.apk

# 3. 拉取到电脑
adb pull <上一步输出的路径> <本地保存路径>
```

### 完整示例

```bash
# 比如提取 v2rayNG
adb shell pm list packages | grep v2ray
# 输出: package:com.v2ray.ang

adb shell pm path com.v2ray.ang
# 输出: package:/data/app/~~abc123/com.v2ray.ang-def456/base.apk

adb pull /data/app/~~abc123/com.v2ray.ang-def456/base.apk C:\Users\admin\Desktop\
```

### 注意事项

- `pm path` 不需要 root 权限
- 拉取到电脑后可以用 jadx 等工具进行反编译分析

---

### push vs install

| 命令 | 用途 |
|------|------|
| `adb push` | 单纯复制文件到手机 |
| `adb install` | 安装 APK（相当于点击安装） |

---

## adb uninstall — 卸载应用

```bash
adb uninstall <包名>
```

### 示例

```bash
adb uninstall com.v2ray.ang
```

> 注意：这里填的是**包名**，不是 APK 文件路径。包名可通过 `adb shell pm list packages` 查询。

---

## adb shell rm — 删除手机上的文件

```bash
adb shell rm <文件路径>
```

### 示例

```bash
# 删除单个文件
adb shell rm /sdcard/test.txt

# 删除文件夹（递归删除）
adb shell rm -rf /sdcard/some_folder/

# 删除需要 root 权限的文件
adb shell su -c "rm /data/local/tmp/frida-server"
```

### 注意事项

- `-r` 递归删除目录，`-f` 强制删除不提示
- `/sdcard/` 下的文件不需要 root，`/data/` 下的通常需要 root
- **rm 删除不可恢复**，操作前确认路径正确

---

## adb shell 写入文本文件

Android 的 adb shell **没有 vim 等文本编辑器**，无法像电脑一样打开文件编辑。

替代方案：

### 方法一：用 echo + 重定向写入（适合简单内容）

```bash
# 写入（覆盖）
adb shell "echo 'hello world' > /sdcard/Documents/test.txt"

# 追加
adb shell "echo '第二行内容' >> /sdcard/Documents/test.txt"

# 写入多行
adb shell "printf 'line1\nline2\nline3\n' > /sdcard/Documents/test.txt"
```

> `>` 是 Shell 重定向符号，把命令的输出从屏幕转向写入文件。`>>` 是追加，`>` 是覆盖。

### 方法二：电脑编辑好再 push（推荐，适合复杂内容）

```bash
# 在电脑上用任意编辑器写好文件，然后推送到手机
adb push C:\Users\admin\Desktop\test.txt /sdcard/Documents/
```

### 为什么没有 vim

- Android 的 shell 环境是精简版的 Linux（toybox），不包含 vim/nano 等编辑器
- 如果需要在手机上编辑文件，可以安装 Termux App，里面可以 `pkg install vim`

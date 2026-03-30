---
name: download-jdk8-temurin
description: 指导在 Windows 上通过 Adoptium Temurin 下载并安装 JDK 8。适用于需要 JDK 8 环境（如 jadx、旧版 Android 工具链）时。Use when the user asks how to install JDK 8, download Java 8, or set up Temurin on Windows.
---

# 在 Windows 上下载并安装 JDK 8（Adoptium Temurin）

## 为什么用 Temurin

- **免登录**：不需要 Oracle 账号，直接下载。
- **开源**：Eclipse Adoptium 提供，TCK 认证的 OpenJDK 发行版。
- **可选**：若必须用 Oracle 官方版，再走 Oracle 归档页（需登录）。

## 下载步骤

### 1. 打开下载页

任选其一（推荐中文页）：

- 中文：<https://adoptium.net/zh-cn/marketplace/?version=8>
- 英文直链：<https://adoptium.net/temurin/releases/?os=windows&arch=x64&package=jdk&version=8>

### 2. 选择版本

在页面上确认或选择：

| 选项     | 选择                  |
| -------- | --------------------- |
| 操作系统 | **Windows**           |
| 架构     | **x64**（64 位）      |
| 包类型   | **JDK**（不要选 JRE） |
| 版本     | **8 - LTS**           |

### 3. 下载安装包

- 点击 **.msi** 安装包进行下载（例如 `OpenJDK8U-jdk_x64_windows_hotspot_8u432b06.msi`）。
- 不要选 .pkg 或 .zip，选 **Windows x64 的 .msi** 便于自动配置环境变量。

### 4. 安装

1. 双击下载好的 .msi，按向导下一步。
2. **建议勾选**：
   - 「Set JAVA_HOME variable」
   - 「Add to PATH」或「JavaSoft (Oracle) registry keys」
3. 安装路径可保持默认（如 `C:\Program Files\Eclipse Adoptium\jdk-8.x.x-hotspot\`），如需自定义可在此步修改。

### 5. 验证

安装完成后**重新打开** PowerShell 或 CMD（使新的 PATH 生效），执行：

```powershell
java -version
javac -version
```

**预期**：能看到 `openjdk version "1.8.0_xxx"` 或 `1.8.x`，且为 64-Bit。

**注意**：JDK 8 只支持 `-version`（一个横线），不支持 `--version`；若输入 `java --version` 会报错 "Unrecognized option: --version"。

## 验证通过标准

- `java -version` 输出包含 1.8 或 8.x 且为 64-Bit。
- `javac -version` 能正常输出版本号。

## 常见问题

| 现象                           | 处理                                                                                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 命令提示「不是内部或外部命令」 | 安装时未勾选「添加到 PATH」，或未重启终端。可重新运行安装程序选「Modify」补选，或手动把 `JAVA_HOME\bin` 加入系统 Path。               |
| 版本不对（不是 1.8）           | 本机可能装过其他 JDK，当前 PATH 优先指向别的版本。检查 `where java` 和 `echo %JAVA_HOME%`，将 JAVA_HOME 指向 Temurin JDK 8 安装目录。 |
| 只有 JRE 没有 javac            | 下载的是 JRE 包而非 JDK。请从上述页面重新选择 **JDK** 再下载安装。                                                                    |

## 简要检查清单

- [ ] 从 Adoptium 下载的是 **JDK**、**Windows x64**、**.msi**
- [ ] 安装时勾选「设置 JAVA_HOME」和「添加到 PATH」
- [ ] 安装后**新开终端**执行 `java -version` 和 `javac -version`
- [ ] 输出为 1.8.x 且 64-Bit

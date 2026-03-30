# Charles 抓包工具 - 下载安装与激活

## 一、Charles 简介

Charles 是一款 HTTP/HTTPS 抓包代理工具，常用于：
- 查看手机/电脑的网络请求和响应
- 分析 API 接口数据
- 调试和逆向分析 App 的网络通信
- 支持 HTTPS 抓包（需安装 CA 证书）

## 二、下载

### 官方下载地址
- 官网：https://www.charlesproxy.com/download/latest-release/
- 最新版本：**v5.0.3**

### Windows 安装包选择
| 格式 | 大小 | 说明 |
|------|------|------|
| appx | ~70.9 MB | 官方推荐格式 |
| msi  | ~65.8 MB | 传统安装包格式 |

选择 **Windows x86_64** 的 msi 或 appx 均可。

## 三、安装

1. 下载完成后双击安装包
2. 按照安装向导一路 Next
3. 可自定义安装路径（默认 `C:\Program Files\Charles\`）
4. 安装完成后启动 Charles

## 四、激活（免费使用）

Charles 试用版有 30 天限制且每次使用 30 分钟后会强制关闭，通过以下方式可永久激活：

### 方法一：在线生成 License Key（推荐）

**步骤：**

1. **访问在线工具**：打开 https://www.zzzmode.com/mytools/charles/
2. **输入版本号**：填入你安装的 Charles 版本号（如 `5.0.3`）
3. **生成 Key**：点击"生成"按钮，复制生成的 **License Key**
4. **注册 Charles**：
   - 打开 Charles
   - 菜单栏 → **Help** → **Register Charles...**
   - **Registered Name** 填任意名字（如你的名字）
   - **License Key** 粘贴刚才生成的 Key
   - 点击 **Register**
5. **重启 Charles**：注册成功后完全关闭并重新打开 Charles

### 方法二：替换 jar 文件

1. 访问在线工具生成新的 `charles.jar` 文件
2. 替换安装目录下的 jar 文件：
   - **Windows 路径**：`C:\Program Files\Charles\lib\charles.jar`
   - 替换前建议备份原文件
3. 重启 Charles

### 验证激活
- 菜单栏 → **Help** → **About Charles**
- 如果显示 **Registered to: 你的名字**，说明激活成功
- 不再出现试用提示弹窗

## 五、基本配置

### 5.1 设置系统代理
Charles 启动后默认会设置为系统代理，监听端口默认 **8888**。

菜单栏 → **Proxy** → **Proxy Settings** 可查看/修改端口。

### 5.2 手机抓包配置
1. 确保手机和电脑在**同一局域网**
2. 查看电脑 IP 地址（`ipconfig`）
3. 手机 Wi-Fi 设置代理：
   - 代理类型：手动
   - 主机名：电脑 IP
   - 端口：8888
4. Charles 弹出连接请求时点击 **Allow**

#### 注意：网络环境问题（多网段）

如果家里有多个路由器形成不同网段（如电脑在 `192.168.1.x`，手机在 `192.168.2.x`），两者**不互通**，手机代理无法连到电脑。

**解决方案：让电脑和手机进入同一网段**

- 禁用电脑的有线以太网连接：`Win+R` → `ncpa.cpl` → 右键以太网 → **禁用**
- 电脑改用 Wi-Fi 连接到手机所在的路由器
- 此时两者在同一局域网，代理可以正常工作

**注意：** 禁用以太网后电脑 IP 会变，需重新用 `ipconfig` 查看 Wi-Fi 的新 IP，并更新手机代理设置。

#### 注意：Clash Verge TUN 模式兼容性

电脑开启 Clash Verge TUN 模式时，Charles 代理仍可正常工作，无需关闭 TUN 模式。

### 5.3 HTTPS 抓包（安装 CA 证书）

默认情况下 HTTPS 内容是加密的，需要安装 Charles 的 CA 证书：

**电脑端：**
- **Help** → **SSL Proxying** → **Install Charles Root Certificate**
- 安装到"受信任的根证书颁发机构"

**手机端：**
- **Help** → **SSL Proxying** → **Install Charles Root Certificate on a Mobile Device**
- 手机浏览器访问 **chls.pro/ssl** 下载并安装证书
- Android 需要到 **设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书** 中安装
- 安装时可以不填名字，显示 `null` 不影响功能

**验证证书已安装：**
- 设置 → 安全 → 加密与凭据 → **受信任的凭据** → **用户** 标签
- 能看到 Charles 相关条目即安装成功

**启用 SSL Proxying：**
- **Proxy** → **SSL Proxying Settings**
- 勾选 **Enable SSL Proxying**
- 添加 `*:443`（抓取所有 HTTPS）或指定域名

### 5.4 Android 7+ 系统证书问题（抓 App 流量必读）

Android 7 开始，**App 默认只信任系统证书，不信任用户证书**。

| 场景 | 用户证书是否有效 |
|------|----------------|
| Chrome 浏览器 | ✅ 有效 |
| 普通 App（如 bilibili 客户端） | ❌ 无效，抓包失败 |

**解决方案：使用 Magisk 模块将用户证书提升为系统证书**

前提条件：设备已 root（安装 Magisk）

**步骤：**
1. 先按上面步骤安装好 Charles 用户 CA 证书
2. 手机下载 `MagiskTrustUserCerts` 模块：
   - GitHub：`NVISOsecurity/MagiskTrustUserCerts`，下载 `.zip` 文件
3. 打开 **Magisk 应用** → **模块** → **从本地安装** → 选择 zip
4. 安装完成后**重启手机**
5. 重启后用户证书自动提升为系统证书，所有 App 均可抓包

## 六、参考链接

- 官网下载：https://www.charlesproxy.com/download/latest-release/
- License Key 在线生成：https://www.zzzmode.com/mytools/charles/
- 博客教程：https://www.cnblogs.com/neozheng/p/18960535
- 博客教程：https://www.cnblogs.com/hahaniuer/p/17915980.html

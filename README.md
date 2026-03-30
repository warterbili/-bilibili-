# Android App Reverse Engineering

安卓应用逆向工程学习项目，以 Bilibili Android 客户端为实战案例。

## 项目结构

```
.
├── docs/                              # 安卓逆向通用教程
│   ├── 01_刷机与环境/                  # BL解锁、刷机、JDK安装
│   ├── 02_工具使用/                    # ADB、Charles、Frida 环境搭建
│   ├── 03_反编译与Hook/               # jadx 反编译、Frida Hook 技术
│   ├── 04_安卓系统知识/               # 系统分区、APK结构、打包流程
│   └── 05_自动化/                     # 手机自动化方案调研
│
├── bilibili/                          # Bilibili 逆向实战
│   ├── docs/                          # 实战笔记（sign、ticket、token、评论接口等）
│   ├── frida_scripts/                 # Frida 脚本集合
│   │   ├── bypass/                    #   反检测绕过（libmsaoaidsec.so）
│   │   ├── hook/                      #   Hook 脚本（sign、appSecret、SSL等）
│   │   ├── trace/                     #   追踪脚本（token、ticket、评论、gRPC）
│   │   └── debug/                     #   调试诊断（pthread、OkHttp、SSL定位）
│   ├── sign_verify/                   # 签名算法逆向验证（Python）
│   ├── auto_comment/                  # 自动评论脚本（Python）
│   ├── packet_capture/                # gRPC/HTTP 抓包数据
│   └── mitmproxy/                     # mitmproxy 中间人代理启动器
│
├── android_automation/                # UIAutomator2 自动化测试
└── tools/                             # 通用工具（Tampermonkey 脚本）
```

## 技术栈

- **逆向工具**: Frida, jadx, Ghidra, Charles, mitmproxy
- **开发语言**: Python, JavaScript (Frida), Java
- **目标设备**: Xiaomi Mi 9 (cepheus) / PixelExperience 13.0
- **关键技术**: SSL Pinning 绕过, 签名算法还原, gRPC 协议分析, JNI Native Hook

## 学习路线

1. **刷机与环境准备** — BL 解锁 → 刷入 PixelExperience → Root (Magisk)
2. **工具链搭建** — ADB/Fastboot → Charles/mitmproxy → Frida
3. **反编译分析** — jadx 静态分析 → Ghidra Native 分析
4. **动态 Hook** — Frida 绕过反检测 → Hook Java/Native 层
5. **协议逆向** — sign 签名还原 → ticket/token 机制 → gRPC 抓包
6. **实战应用** — 评论接口完整逆向 → 自动评论脚本

## License

MIT

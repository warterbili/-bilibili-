"""
一键启动 mitmweb 抓包脚本
启动：系统代理 → mitmproxy → Clash(7897) → 外网
关闭（Ctrl+C）：还原系统代理给 Clash
"""

import subprocess
import winreg
import ctypes

# ====== 配置 ======
CLASH_PORT = 7897
MITM_PORT = 8080
WEB_PORT = 8081
# ==================

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def set_system_proxy(server):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
    winreg.CloseKey(key)
    # 通知系统立即生效
    inet = ctypes.windll.wininet.InternetSetOptionW
    inet(0, 39, 0, 0)
    inet(0, 37, 0, 0)


def main():
    mitm = f"127.0.0.1:{MITM_PORT}"
    clash = f"127.0.0.1:{CLASH_PORT}"

    print(f"[*] 系统代理 -> {mitm}")
    set_system_proxy(mitm)

    print(f"[*] mitmweb 启动中 (代理:{MITM_PORT} Web:{WEB_PORT})")
    print(f"[*] 上游: Clash ({clash})")
    print(f"[*] 打开 http://127.0.0.1:{WEB_PORT} 查看抓包")
    print(f"[*] Ctrl+C 停止并还原\n")

    try:
        proc = subprocess.Popen([
            "mitmweb",
            "--mode", f"upstream:http://{clash}",
            "--listen-port", str(MITM_PORT),
            "--web-port", str(WEB_PORT),
        ])
        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] 停止 mitmweb...")
        proc.terminate()
        proc.wait()
    finally:
        print(f"[*] 还原系统代理 -> {clash}")
        set_system_proxy(clash)
        print("[*] 已还原")


if __name__ == "__main__":
    main()

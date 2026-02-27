"""
verify_sign2.py - 多方案验证 B站 sign
尝试各种参数组合 + 已知 appSecret 列表
"""

import hashlib
import urllib.parse
import itertools

RAW_BODY = "access_key=9268870d42b7212148710905156f8721CjBAOXQgCc4BjdOWMhzO1XMnYPwB5At5FpWjZIFID3L9apB7zCEPGPqZaXO67V0hJM4SVnYtQTREVWJSVmZ1M2RfWUFEcGhvUmhMZlZRdHl0N3R3dnplWkVxRENOVVU4ckxGM1RqZWVnMndZdS1ZeVkwNExWVWlYcHVqNkxZUDhqVUhDeWJSenpBIIEC&appkey=1d8b6e7d45233436&build=8830500&c_locale=zh-Hans_CN&channel=html5_search_google&container_uuid=a535fbad-fca9-4775-86bc-84b8fb885017&disable_rcmd=0&from_spmid=tm.recommend.0.0&goto=vertical_av&has_vote_option=false&message=%E5%93%88%E5%93%88&mobi_app=android&oid=116063807212606&ordering=heat&plat=2&platform=android&s_locale=zh-Hans_CN&scene=main&scm_action_id=50051A9E&spmid=main.ugc-video-detail-vertical.0.0&statistics=%7B%22appId%22%3A1%2C%22platform%22%3A3%2C%22version%22%3A%228.83.0%22%2C%22abtest%22%3A%22%22%7D&sync_to_dynamic=false&track_id=all_0.router-pegasus-2479124-l46t4.1771442830538.472&ts=1771442847&type=1&sign=83f5e24c3e2a92761f06d274ff412fb2"

TARGET_SIGN = "83f5e24c3e2a92761f06d274ff412fb2"

# 历史上已知的 B站 appSecret（公开资料）
KNOWN_SECRETS = [
    "560c52ccd288fed045859ed18bffd973",   # Android 老版本
    "ea85624dfcf12d7cc7b2b3a94fac1f2c",   # 另一个历史版本
    "59b43e04ad6965f34319062b478f83dd",   # Web端
    "8e9fc618fbd41a0d8cda9ab5e09d752f",   # 另一个
]

# 可能不参与 sign 的 tracking 类参数
TRACKING_KEYS = {
    "container_uuid", "track_id", "from_spmid", "spmid",
    "scm_action_id", "goto", "ordering", "scene", "statistics",
    "sync_to_dynamic", "has_vote_option", "c_locale", "s_locale", "channel"
}

def parse_params(raw: str, decode_values=True):
    params = {}
    for pair in raw.strip().split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        params[k] = urllib.parse.unquote_plus(v) if decode_values else v
    return params

def calc_sign(params: dict, secret: str) -> str:
    s = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.md5((s + secret).encode("utf-8")).hexdigest()

def try_combo(label: str, params: dict, secret: str):
    sign = calc_sign(params, secret)
    if sign == TARGET_SIGN:
        print(f"\n✅✅✅ 找到！方案：{label}")
        print(f"   appSecret: {secret}")
        print(f"   参数数量: {len(params)}")
        return True
    return False

# 解析两种版本
params_decoded = parse_params(RAW_BODY, decode_values=True)
params_encoded = parse_params(RAW_BODY, decode_values=False)
params_decoded.pop("sign", None)
params_encoded.pop("sign", None)

print(f"[*] 共 {len(params_decoded)} 个参数（不含 sign）")
print(f"[*] 目标 sign: {TARGET_SIGN}")
print(f"[*] 开始穷举...\n")

found = False

for secret in KNOWN_SECRETS:
    # 方案A：全参数 + 值已解码
    if try_combo(f"全参数/值解码 secret={secret[:8]}...", params_decoded, secret):
        found = True; break
    # 方案B：全参数 + 值保持编码
    if try_combo(f"全参数/值编码 secret={secret[:8]}...", params_encoded, secret):
        found = True; break

    # 方案C：去掉 tracking 参数 + 值解码
    core_decoded = {k: v for k, v in params_decoded.items() if k not in TRACKING_KEYS}
    if try_combo(f"核心参数/值解码({len(core_decoded)}个) secret={secret[:8]}...", core_decoded, secret):
        found = True; break
    # 方案D：去掉 tracking 参数 + 值编码
    core_encoded = {k: v for k, v in params_encoded.items() if k not in TRACKING_KEYS}
    if try_combo(f"核心参数/值编码({len(core_encoded)}个) secret={secret[:8]}...", core_encoded, secret):
        found = True; break

if not found:
    print("❌ 所有已知 appSecret 均不匹配")
    print("\n[*] 核心参数（可能参与 sign）：")
    core = {k: v for k, v in params_decoded.items() if k not in TRACKING_KEYS}
    for k, v in sorted(core.items()):
        print(f"    {k} = {v[:60]}{'...' if len(v)>60 else ''}")
    print(f"\n[*] 核心参数 MD5 输入预览（secret=560c52...）：")
    s = "&".join(f"{k}={v}" for k, v in sorted(core.items()))
    print(f"    {(s + KNOWN_SECRETS[0])[:200]}")
    print("\n→ 下一步：jadx 静态找真实 appSecret")

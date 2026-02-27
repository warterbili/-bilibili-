"""
verify_sign.py - 验证 B站 sign 算法

用法：
  1. 把抓包到的请求 body（URL 编码格式）粘贴到 RAW_BODY
  2. 运行脚本，输出是否匹配
"""

import hashlib
import urllib.parse

# ─── 把抓包的原始 body 粘贴到这里 ──────────────────────────────
# 格式：key1=val1&key2=val2&...&sign=xxx
RAW_BODY = """
access_key=9268870d42b7212148710905156f8721CjBAOXQgCc4BjdOWMhzO1XMnYPwB5At5FpWjZIFID3L9apB7zCEPGPqZaXO67V0hJM4SVnYtQTREVWJSVmZ1M2RfWUFEcGhvUmhMZlZRdHl0N3R3dnplWkVxRENOVVU4ckxGM1RqZWVnMndZdS1ZeVkwNExWVWlYcHVqNkxZUDhqVUhDeWJSenpBIIEC&appkey=1d8b6e7d45233436&build=8830500&c_locale=zh-Hans_CN&channel=html5_search_google&container_uuid=a535fbad-fca9-4775-86bc-84b8fb885017&disable_rcmd=0&from_spmid=tm.recommend.0.0&goto=vertical_av&has_vote_option=false&message=%E5%93%88%E5%93%88&mobi_app=android&oid=116063807212606&ordering=heat&plat=2&platform=android&s_locale=zh-Hans_CN&scene=main&scm_action_id=50051A9E&spmid=main.ugc-video-detail-vertical.0.0&statistics=%7B%22appId%22%3A1%2C%22platform%22%3A3%2C%22version%22%3A%228.83.0%22%2C%22abtest%22%3A%22%22%7D&sync_to_dynamic=false&track_id=all_0.router-pegasus-2479124-l46t4.1771442830538.472&ts=1771442847&type=1&sign=83f5e24c3e2a92761f06d274ff412fb2
"""
# ────────────────────────────────────────────────────────────────

# 历史公开的 appSecret（对应 appkey=1d8b6e7d45233436）
APP_SECRET = "560c52ccd288fed045859ed18bffd973"


def verify(raw_body: str, app_secret: str):
    raw_body = raw_body.strip()

    # 1. 解析所有参数
    params = {}
    for pair in raw_body.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        params[k] = urllib.parse.unquote_plus(v)

    # 2. 提取 sign，从参数里移除
    captured_sign = params.pop("sign", None)
    if not captured_sign:
        print("[!] body 里没找到 sign 字段")
        return

    print(f"[*] 共解析到 {len(params)} 个参数（不含 sign）：")
    for k, v in sorted(params.items()):
        print(f"    {k} = {v}")

    # 3. 按 key 字母序排列，拼成 query string（值用原始字符串，不 URL 编码）
    sorted_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    to_hash = sorted_str + app_secret

    print(f"\n[*] 待 MD5 字符串：\n    {to_hash[:200]}{'...' if len(to_hash) > 200 else ''}")

    # 4. MD5
    computed_sign = hashlib.md5(to_hash.encode("utf-8")).hexdigest()

    print(f"\n[*] 抓包 sign：  {captured_sign}")
    print(f"[*] 计算 sign：  {computed_sign}")

    if computed_sign == captured_sign:
        print("\n✅ 验证成功！算法正确，appSecret 正确")
    else:
        print("\n❌ 不匹配，可能原因：")
        print("   1. 参数不完整（抓包 body 里有参数没复制进来）")
        print("   2. appSecret 已更新（需要 jadx 静态找新值）")
        print("   3. 参数值编码方式不同（空格用 + 还是 %20）")


if __name__ == "__main__":
    verify(RAW_BODY, APP_SECRET)

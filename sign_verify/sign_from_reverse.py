"""
sign_from_reverse.py
====================
纯逆向分析还原的 B站 sign 算法，不依赖任何网络公开资料。

逆向路径：
  Java: LibBili.signQuery(TreeMap) → LibBili.s(SortedMap) [native]
  JNI 入口:  FUN_00109050  (libbili.so +0x9050，RegisterNatives 确认)
  包装层1:   FUN_0011629c  (透传参数)
  包装层2:   FUN_001162a8  (OLLVM 主函数，状态机)
    ├─ FUN_00117de4  → 序列化 SortedMap 为 "key=val&..." 字符串（JNI 调用）
    ├─ FUN_0011605c  → 从数据表按 appkey 版本选取 appSecret（4 个 uint32_t）
    └─ FUN_00118ff0  → MD5 计算（静态分析可完整读懂）
         MD5_Init  = FUN_0010ffac
         MD5_Update = FUN_0010ffc0
         MD5_Final  = FUN_00112dd0
         格式字符串由 Frida hook_sprintf.js 确认：
           DAT_001d8844 = "%08x"  （appSecret uint32_t → 8字符hex，4次）
           DAT_001d8cbc = "%02x"  （MD5摘要字节 → 2字符hex，16次）

appSecret 来源：
  FUN_0011605c 返回数据块指针，FUN_001162a8 以偏移 0/0x13/0x26/0x39
  读出 4 个 uint32_t，由 Frida hook_appsecret.js 在运行时直接读取确认：
    secret[0] = 0x560c52cc → "560c52cc"
    secret[1] = 0xd288fed0 → "d288fed0"
    secret[2] = 0x45859ed1 → "45859ed1"
    secret[3] = 0x8bffd973 → "8bffd973"
  拼接 = "560c52ccd288fed045859ed18bffd973"
"""

from bili_sign import make_sign, sign_params  # noqa: F401  算法实现在 bili_sign.py


# ── 验证：用抓包数据测试 ────────────────────────────────────────
if __name__ == "__main__":
    # 来自 ssl_hook.js 抓包的请求参数（原始值，make_sign 内部会 URL 编码）
    params = {
        "access_key":     "9268870d42b7212148710905156f8721CjBAOXQgCc4BjdOWMhzO1XMnYPwB5At5FpWjZIFID3L9apB7zCEPGPqZaXO67V0hJM4SVnYtQTREVWJSVmZ1M2RfWUFEcGhvUmhMZlZRdHl0N3R3dnplWkVxRENOVVU4ckxGM1RqZWVnMndZdS1ZeVkwNExWVWlYcHVqNkxZUDhqVUhDeWJSenpBIIEC",
        "appkey":         "1d8b6e7d45233436",
        "build":          "8830500",
        "c_locale":       "zh-Hans_CN",
        "channel":        "html5_search_google",
        "container_uuid": "a535fbad-fca9-4775-86bc-84b8fb885017",
        "disable_rcmd":   "0",
        "from_spmid":     "tm.recommend.0.0",
        "goto":           "vertical_av",
        "has_vote_option":"false",
        "message":        "哈哈",
        "mobi_app":       "android",
        "oid":            "116063807212606",
        "ordering":       "heat",
        "plat":           "2",
        "platform":       "android",
        "s_locale":       "zh-Hans_CN",
        "scene":          "main",
        "scm_action_id":  "50051A9E",
        "spmid":          "main.ugc-video-detail-vertical.0.0",
        "statistics":     '{"appId":1,"platform":3,"version":"8.83.0","abtest":""}',
        "sync_to_dynamic":"false",
        "track_id":       "all_0.router-pegasus-2479124-l46t4.1771442830538.472",
        "ts":             "1771442847",
        "type":           "1",
    }

    sign = make_sign(params)
    expected = "83f5e24c3e2a92761f06d274ff412fb2"

    print("=" * 60)
    print("B站 sign 算法还原验证")
    print("=" * 60)
    print(f"计算 sign：{sign}")
    print(f"抓包 sign：{expected}")

    if sign == expected:
        print("\n✅ 算法还原成功！与抓包值完全吻合")
    else:
        print("\n❌ 不匹配，请检查 bili_sign.py")

"""
verify_both.py - 用新抓包数据同时验证两个 sign 算法
"""

from bili_sign import make_sign as sign_reverse
from bili_sign_opensource import make_sign as sign_opensource
from urllib.parse import unquote


def verify(label, params, target):
    """验证一组抓包数据"""
    print(f"\n{'='*60}")
    print(f"验证：{label}")
    print(f"{'='*60}")
    print(f"目标 sign：{target}")
    print(f"参数数量：{len(params)}")

    r = sign_reverse(params)
    o = sign_opensource(params)
    print(f"\n  [逆向] {r}  {'✅' if r == target else '❌'}")
    print(f"  [公开] {o}  {'✅' if o == target else '❌'}")
    if r == o:
        print(f"  两方案一致 ✓")


# ── 抓包 #1（2026-02-20 第2次）───────────────────────────────
params1 = {
    "access_key":     "9268870d42b7212148710905156f8721CjBAOXQgCc4BjdOWMhzO1XMnYPwB5At5FpWjZIFID3L9apB7zCEPGPqZaXO67V0hJM4SVnYtQTREVWJSVmZ1M2RfWUFEcGhvUmhMZlZRdHl0N3R3dnplWkVxRENOVVU4ckxGM1RqZWVnMndZdS1ZeVkwNExWVWlYcHVqNkxZUDhqVUhDeWJSenpBIIEC",
    "appkey":         "1d8b6e7d45233436",
    "build":          "8830500",
    "c_locale":       "zh-Hans_CN",
    "channel":        "html5_search_google",
    "container_uuid": "39cd2a3f-30f1-417a-9972-88214ef1b248",
    "disable_rcmd":   "0",
    "from_spmid":     "ad.tianma.tm-recommendation-card.0",
    "has_vote_option": "false",
    "message":        "哈哈",
    "mobi_app":       "android",
    "oid":            "115621979232790",
    "ordering":       "heat",
    "plat":           "2",
    "platform":       "android",
    "s_locale":       "zh-Hans_CN",
    "scene":          "main",
    "scm_action_id":  "E3A67019",
    "spmid":          "united.player-video-detail.0.0",
    "statistics":     '{"appId":1,"platform":3,"version":"8.83.0","abtest":""}',
    "sync_to_dynamic": "false",
    "track_id":       "all_0.router-pegasus-2479124-l46t4.1771517436204.261",
    "ts":             "1771517477",
    "type":           "1",
}

# ── 抓包 #2（2026-02-20 第3次，完整 HEADERS 版）──────────────
params2 = {
    "access_key":     "9268870d42b7212148710905156f8721CjBAOXQgCc4BjdOWMhzO1XMnYPwB5At5FpWjZIFID3L9apB7zCEPGPqZaXO67V0hJM4SVnYtQTREVWJSVmZ1M2RfWUFEcGhvUmhMZlZRdHl0N3R3dnplWkVxRENOVVU4ckxGM1RqZWVnMndZdS1ZeVkwNExWVWlYcHVqNkxZUDhqVUhDeWJSenpBIIEC",
    "appkey":         "1d8b6e7d45233436",
    "build":          "8830500",
    "c_locale":       "zh-Hans_CN",
    "channel":        "html5_search_google",
    "container_uuid": "4866a0c3-c05d-4ecf-bcf9-d663452d16ce",
    "disable_rcmd":   "0",
    "from_spmid":     "tm.recommend.0.0",
    "has_vote_option": "false",
    "message":        unquote("%5B%E7%AC%91%E5%93%AD%5D"),  # [笑哭]
    "mobi_app":       "android",
    "oid":            "116083721768888",
    "ordering":       "heat",
    "plat":           "2",
    "platform":       "android",
    "s_locale":       "zh-Hans_CN",
    "scene":          "main",
    "scm_action_id":  "E89F0ACA",
    "spmid":          "united.player-video-detail.0.0",
    "statistics":     '{"appId":1,"platform":3,"version":"8.83.0","abtest":""}',
    "sync_to_dynamic": "false",
    "track_id":       "all_0.router-pegasus-2479124-2dxd2.1771518418621.379",
    "ts":             "1771518449",
    "type":           "1",
}

TARGET_SIGN = "f7caaf24e83407a8bff4d3067afd20f5"

verify("抓包#1 message=哈哈 oid=115621979232790",
       params1, "f7caaf24e83407a8bff4d3067afd20f5")

verify("抓包#2 message=[笑哭] oid=116083721768888",
       params2, "75dfbb297d4634ee9d60804e170fa557")

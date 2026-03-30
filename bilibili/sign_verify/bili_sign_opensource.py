"""
bili_sign_opensource.py
======================
B站 sign 算法 — 网上公开方案（传统拼接法）

来源：公开资料 / bilibili-API-collect 等社区总结
算法：MD5(sorted_params + appSecret)
  - 参数按 key 字母序排列
  - value 保持 URL 编码形式（即抓包原始值，不做 unquote）
  - 末尾直接拼接 appSecret 字符串
  - 整体 MD5

与逆向方案 (bili_sign.py) 的区别：
  - 本方案：MD5( "k1=v1&k2=v2&..." + secret )  一次性拼接
  - 逆向方案：MD5_Update(sorted_params) + 4×MD5_Update("%08x" % uint32)  流式更新
  两者在 secret = "%08x"*4 连接结果时，数学上等价
"""

import hashlib
from urllib.parse import quote


# 公开已知的 B站 appSecret 列表
KNOWN_SECRETS = {
    "android_current": "560c52ccd288fed045859ed18bffd973",
    "android_old":     "ea85624dfcf12d7cc7b2b3a94fac1f2c",
    "web":             "59b43e04ad6965f34319062b478f83dd",
    "other":           "8e9fc618fbd41a0d8cda9ab5e09d752f",
}

# 默认使用当前 Android 版本的 secret
_DEFAULT_SECRET = KNOWN_SECRETS["android_current"]


def make_sign(params: dict, secret: str = _DEFAULT_SECRET) -> str:
    """
    计算 B站请求 sign（公开方案）。

    算法：
      1. 按 key 字母序排列
      2. value 做 URL 编码
      3. 拼接为 "k1=v1&k2=v2&..."
      4. 末尾追加 appSecret
      5. 整体 MD5

    Args:
        params: 请求参数 dict（原始值，函数内部做 URL 编码）
        secret: appSecret 字符串，默认为当前 Android 版本

    Returns:
        32 字符小写 hex sign
    """
    sorted_params = "&".join(
        f"{k}={quote(str(v), safe='')}"
        for k, v in sorted(params.items())
    )
    return hashlib.md5((sorted_params + secret).encode("utf-8")).hexdigest()


def sign_params(params: dict, secret: str = _DEFAULT_SECRET) -> dict:
    """在参数 dict 中加入 sign 字段后返回新 dict。"""
    result = dict(params)
    result["sign"] = make_sign(params, secret)
    return result

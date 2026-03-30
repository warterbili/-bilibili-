"""
bili_sign.py
============
B站 sign 算法模块（纯逆向还原，可复用）

用法：
    from bili_sign import make_sign, sign_params

    # 只计算 sign 值
    sign = make_sign({"ts": "1234", "appkey": "...", ...})

    # 在参数里直接加上 sign 字段（最常用）
    params = {"ts": "1234", "appkey": "...", ...}
    signed = sign_params(params)
    # → {"ts": "1234", "appkey": "...", ..., "sign": "xxxx..."}
"""

import hashlib
from urllib.parse import quote


# ── appSecret（Frida hook_appsecret.js 从 FUN_00118ff0 args[3] 动态读取）
# libbili.so FUN_0011605c 返回数据块，FUN_001162a8 以偏移 0/0x13/0x26/0x39 读出
_SECRET_UINT32 = [0x560c52cc, 0xd288fed0, 0x45859ed1, 0x8bffd973]
# 展开后 = "560c52ccd288fed045859ed18bffd973"


def make_sign(params: dict) -> str:
    """
    计算 B站请求 sign。

    还原路径（libbili.so）：
      FUN_00109050 → FUN_0011629c → FUN_001162a8 (OLLVM)
        ├─ FUN_00117de4 : SortedMap → "key=url_encoded_val&..." 字符串
        ├─ FUN_0011605c : 按 appkey 版本取 appSecret (4×uint32_t)
        └─ FUN_00118ff0 : MD5 计算
             MD5_Update(sorted_params)
             for i in 0..3: MD5_Update(sprintf("%08x", secret[i]))  ← DAT_001d8844
             MD5_Final → sprintf("%02x"×16)                          ← DAT_001d8cbc

    Args:
        params: 请求参数 dict（原始值，不需要提前 URL 编码）

    Returns:
        32 字符的小写 hex sign 字符串
    """
    # Step 1：按 key 字母序排序，value URL 编码后拼接
    # FUN_00117de4 通过 JNI 序列化 TreeMap，对值做 URL 编码
    # 验证：message=哈哈 → %E5%93%88%E5%93%88，statistics={...} → %7B...%7D
    sorted_params = "&".join(
        f"{k}={quote(str(v), safe='')}"
        for k, v in sorted(params.items())
    )

    # Step 2：MD5 streaming（FUN_00118ff0）
    ctx = hashlib.md5()
    ctx.update(sorted_params.encode("utf-8"))          # MD5_Update(sorted_params)

    for v in _SECRET_UINT32:                           # 4 次循环
        ctx.update(("%08x" % v).encode("utf-8"))       # MD5_Update(sprintf("%08x"))

    return ctx.hexdigest()                             # MD5_Final + %02x×16


def sign_params(params: dict) -> dict:
    """
    在参数 dict 中加入 sign 字段后返回新 dict（不修改原 dict）。

    Args:
        params: 请求参数（不含 sign 字段）

    Returns:
        包含 sign 字段的新 dict
    """
    result = dict(params)
    result["sign"] = make_sign(params)
    return result

"""
bili_ticket.py
==============
x-bili-ticket 刷新模块。

调用 B站 GenWebTicket 接口获取/刷新 ticket（JWT）。
Android 端使用 key_id="ec01", HMAC key="Ezlc3tgtl"。

用法：
    from bili_ticket import gen_ticket, is_ticket_valid

    ticket_info = gen_ticket()   # {"value": "eyJ...", "created_at": ..., "ttl": ...}
    still_ok = is_ticket_valid(ticket_info)
"""

import hmac
import hashlib
import time
import json

import httpx

# ── Android 端密钥 ──────────────────────────────────────
_KEY_ID = "ec01"
_HMAC_KEY = b"Ezlc3tgtl"

_TICKET_URL = "https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket"
_UA = (
    "Mozilla/5.0 BiliDroid/8.83.0 (bbcallen@gmail.com) 8.83.0 "
    "os/android model/MI 9 mobi_app/android build/8830500 "
    "channel/html5_search_google innerVer/8830510 osVer/13 network/2"
)


def gen_ticket() -> dict:
    """
    请求新的 x-bili-ticket。

    Returns:
        {"value": str, "created_at": int, "ttl": int}

    Raises:
        RuntimeError: 接口返回非 0 code
    """
    ts = int(time.time())
    # hexsign = HMAC-SHA256(key, "ts" + timestamp_str)
    hexsign = hmac.new(_HMAC_KEY, f"ts{ts}".encode(), hashlib.sha256).hexdigest()

    params = {
        "key_id": _KEY_ID,
        "hexsign": hexsign,
        "context[ts]": ts,
    }

    resp = httpx.post(
        _TICKET_URL, params=params, headers={"User-Agent": _UA}, timeout=10
    )
    data = resp.json()

    if data.get("code") != 0:
        raise RuntimeError(f"GenWebTicket failed: {data}")

    d = data["data"]
    return {
        "value": d["ticket"],
        "created_at": d["created_at"],
        "ttl": d["ttl"],
    }


def is_ticket_valid(ticket_info: dict, margin: int = 300) -> bool:
    """
    检查 ticket 是否仍有效（提前 margin 秒刷新）。

    Args:
        ticket_info: {"value": str, "created_at": int, "ttl": int}
        margin: 提前刷新秒数，默认 300（5 分钟）

    Returns:
        True 表示仍可用
    """
    if not ticket_info.get("value"):
        return False
    expire_at = ticket_info["created_at"] + ticket_info["ttl"]
    return time.time() < (expire_at - margin)


# ── CLI 入口：单独运行可测试 ticket 获取 ──────────────────
if __name__ == "__main__":
    print("正在获取 x-bili-ticket ...")
    info = gen_ticket()
    print(f"ticket : {info['value'][:50]}...")
    print(f"created: {info['created_at']}")
    print(f"ttl    : {info['ttl']}s ({info['ttl'] // 3600}h)")
    print(f"valid  : {is_ticket_valid(info)}")

    # 可选：回写到 config.json
    import pathlib
    cfg_path = pathlib.Path(__file__).parent / "config.json"
    if cfg_path.exists():
        cfg = json.loads(cfg_path.read_text("utf-8"))
        cfg["ticket"] = info
        cfg_path.write_text(json.dumps(cfg, indent=4, ensure_ascii=False), "utf-8")
        print(f"\n已回写 ticket 到 {cfg_path}")

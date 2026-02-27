"""
bili_comment.py
===============
B站自动评论主脚本。

构造完整的 27 个请求头 + 24 个请求体参数，调用 /x/v2/reply/add 发送评论。
body 编码严格与 sign 计算保持一致（手工 URL 编码 + content= 发送）。

用法：
    python bili_comment.py <oid> <message>
    python bili_comment.py 116083721768888 "测试评论"
"""

import json
import sys
import time
import uuid
import secrets
import pathlib
from urllib.parse import quote

import httpx

# ── 导入签名模块 ─────────────────────────────────────────
# bili_sign.py 位于 ../sign_verify/
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sign_verify.bili_sign import sign_params

# ── 导入 ticket 模块 ──────────────────────────────────────
from bili_ticket import gen_ticket, is_ticket_valid

# ── 常量 ──────────────────────────────────────────────────
_COMMENT_URL = "https://api.bilibili.com/x/v2/reply/add"
_CONFIG_PATH = pathlib.Path(__file__).parent / "config.json"


class BiliComment:
    """B站评论发送器。"""

    def __init__(self, config_path: str | pathlib.Path = _CONFIG_PATH):
        self.config_path = pathlib.Path(config_path)
        self.cfg = json.loads(self.config_path.read_text("utf-8"))
        self.client = httpx.Client(http1=True, timeout=15)

    def _save_config(self):
        """回写 config（主要用于更新 ticket）。"""
        self.config_path.write_text(
            json.dumps(self.cfg, indent=4, ensure_ascii=False), "utf-8"
        )

    def ensure_ticket(self) -> str:
        """检查/刷新 ticket，返回有效的 ticket 值。"""
        ticket_info = self.cfg.get("ticket", {})
        if not is_ticket_valid(ticket_info):
            print("[ticket] 已过期或为空，正在刷新...")
            ticket_info = gen_ticket()
            self.cfg["ticket"] = ticket_info
            self._save_config()
            print(f"[ticket] 刷新成功，ttl={ticket_info['ttl']}s")
        return ticket_info["value"]

    def _build_headers(self, ticket: str, body_len: int) -> dict:
        """构造全部请求头。"""
        dev = self.cfg["device"]
        fp = self.cfg["fingerprint"]
        mid = self.cfg["mid"]
        buvid = self.cfg["buvid"]

        # session_id: 8 位随机 hex
        session_id = secrets.token_hex(4)

        # x-bili-trace-id: 每次请求生成新值（base64 编码的追踪标识）
        # 简化处理：用随机 bytes 生成
        import base64
        trace_bytes = secrets.token_bytes(21)
        trace_id = base64.b64encode(trace_bytes).decode()

        ua = (
            f"Mozilla/5.0 BiliDroid/{dev['app_ver']} (bbcallen@gmail.com) "
            f"{dev['app_ver']} os/android model/{dev['model']} "
            f"mobi_app/{dev['mobi_app']} build/{dev['build']} "
            f"channel/{dev['channel']} innerVer/{dev['build']}10 "
            f"osVer/{dev['os_ver']} network/2"
        )

        return {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "app-key": "android64",
            "bili-http-engine": "ignet",
            "buvid": buvid,
            "content-length": str(body_len),
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "env": "prod",
            "fp_local": fp["fp_local"],
            "fp_remote": fp["fp_remote"],
            "guestid": fp["guestid"],
            "session_id": session_id,
            "user-agent": ua,
            "x-bili-aurora-eid": fp["aurora_eid"],
            "x-bili-locale-bin": fp["locale_bin"],
            "x-bili-metadata-ip-region": "CN",
            "x-bili-metadata-legal-region": "CN",
            "x-bili-mid": str(mid),
            "x-bili-trace-id": trace_id,
            "x-bili-redirect": "1",
            "x-bili-ticket": ticket,
        }

    def _build_params(self, oid: str, message: str, type_: int = 1) -> dict:
        """构造 24 个请求体参数（不含 sign）。"""
        dev = self.cfg["device"]
        ts = int(time.time())

        # statistics JSON
        statistics = json.dumps(
            {"appId": 1, "platform": 3, "version": dev["app_ver"], "abtest": ""},
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return {
            "access_key": self.cfg["access_key"],
            "appkey": "1d8b6e7d45233436",
            "build": dev["build"],
            "c_locale": "zh-Hans_CN",
            "channel": dev["channel"],
            "container_uuid": str(uuid.uuid4()),
            "disable_rcmd": "0",
            "from_spmid": "tm.recommend.0.0",
            "has_vote_option": "false",
            "message": message,
            "mobi_app": dev["mobi_app"],
            "oid": str(oid),
            "ordering": "heat",
            "plat": "2",
            "platform": dev["platform"],
            "s_locale": "zh-Hans_CN",
            "scene": "main",
            "scm_action_id": secrets.token_hex(4).upper(),
            "spmid": "united.player-video-detail.0.0",
            "statistics": statistics,
            "sync_to_dynamic": "false",
            "track_id": "",
            "ts": str(ts),
            "type": str(type_),
        }

    def post_comment(self, oid: str, message: str, type_: int = 1) -> dict:
        """
        发送评论。

        Args:
            oid: 目标视频/内容 ID
            message: 评论内容
            type_: 内容类型，1=视频评论

        Returns:
            API 响应 JSON dict
        """
        # 1. 确保 ticket 有效
        ticket = self.ensure_ticket()

        # 2. 构造参数并签名
        params = self._build_params(oid, message, type_)
        signed = sign_params(params)

        # 3. 手工编码 body（与 sign 计算方式完全一致）
        body = "&".join(
            f"{k}={quote(str(v), safe='')}"
            for k, v in sorted(signed.items())
        )
        body_bytes = body.encode("utf-8")

        # 4. 构造请求头
        headers = self._build_headers(ticket, len(body_bytes))

        # 5. 发送请求
        print(f"[comment] POST {_COMMENT_URL}")
        print(f"[comment] oid={oid}, message={message!r}, body_len={len(body_bytes)}")

        resp = self.client.post(_COMMENT_URL, content=body_bytes, headers=headers)
        result = resp.json()

        # 6. 处理响应
        code = result.get("code", -1)
        if code == 0:
            rpid = result.get("data", {}).get("rpid", "?")
            print(f"[comment] 成功! rpid={rpid}")
        elif code == -101:
            print(f"[comment] 失败: code={code} (access_key 过期，需重新抓包)")
        elif code == -111:
            print(f"[comment] 失败: code={code} (csrf 校验失败)")
        elif code == -412:
            print(f"[comment] 失败: code={code} (请求被拦截，可能触发风控)")
        else:
            print(f"[comment] 失败: code={code}, msg={result.get('message', '?')}")

        return result


# ── CLI 入口 ──────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python bili_comment.py <oid> <message>")
        print("示例: python bili_comment.py 116083721768888 \"测试评论\"")
        sys.exit(1)

    oid = sys.argv[1]
    message = sys.argv[2]

    bc = BiliComment()
    result = bc.post_comment(oid, message)
    print(json.dumps(result, indent=2, ensure_ascii=False))

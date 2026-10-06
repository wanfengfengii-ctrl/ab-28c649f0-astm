#!/usr/bin/env python3
"""对运行中的 API 执行端到端冒烟：合法会话（跨块 + 重传）与各类拒绝路径。"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tests.test_astm import frame  # noqa: E402

BASE = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
PATH = "/api/astm/sessions/audit"

failures: list[str] = []


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def split_bytes(data: bytes, sizes=(2, 1, 3, 1, 2, 4)) -> list[bytes]:
    out: list[bytes] = []
    pos = 0
    k = 0
    while pos < len(data):
        size = sizes[k % len(sizes)]
        out.append(data[pos : pos + size])
        pos += size
        k += 1
    return out


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        failures.append(name)


def post(chunks, sender="LX-01"):
    body = json.dumps({"sender": sender, "chunks": chunks}).encode("utf-8")
    req = urllib.request.Request(
        BASE + PATH, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def send_parts(data: bytes) -> list[dict]:
    return [{"direction": "send", "data": b64(p)} for p in split_bytes(data)]


print("== 合法会话：ENQ(跨块) / NAK 重传 / 帧体跨块 / EOT ==")
chunks: list[dict] = []
chunks += send_parts(b"\x05")
chunks.append({"direction": "recv", "data": b64(b"\x06")})

f1 = frame(b"H|\\^&|||CHEM-1|||||||||", 1)
chunks += send_parts(f1)                       # 首帧落在多个块中
chunks.append({"direction": "recv", "data": b64(b"\x15")})
chunks.append({"direction": "send", "data": b64(f1)})   # 原样重传（整块）
chunks.append({"direction": "recv", "data": b64(b"\x06")})

f2 = frame(b"O|1||^^^GLU|R|||||||||||", 2)
chunks += send_parts(f2)
chunks.append({"direction": "recv", "data": b64(b"\x06")})

f3 = frame(b"R|1|^^^GLU|5.2|mmol/L||N", 3, term=0x03)
chunks += send_parts(f3)
chunks.append({"direction": "recv", "data": b64(b"\x06")})
chunks += send_parts(b"\x04")                  # EOT 也跨块

status, body = post(chunks)
expected = (
    b"H|\\^&|||CHEM-1|||||||||"
    b"O|1||^^^GLU|R|||||||||||"
    b"R|1|^^^GLU|5.2|mmol/L||N"
)
check("HTTP 200", status == 200, str(body))
check("ok=true", body.get("ok") is True, str(body))
check("帧数=3", body.get("frame_count") == 3, str(body))
check("重传=1", body.get("retransmissions") == 1, str(body))
check("重组正文", body.get("body") == expected.decode("latin-1"), str(body.get("body")))
check("SHA-256", body.get("sha256") == hashlib.sha256(expected).hexdigest(), str(body))


def expect_reject(name, chunks, code, http_status=422):
    status, body = post(chunks)
    err = body.get("error", {})
    ok = (
        status == http_status
        and err.get("code") == code
        and isinstance(err.get("block_index"), int)
        and isinstance(err.get("position"), int)
    )
    check(name, ok, f"status={status} body={body}")


print("== 拒绝路径 ==")
expect_reject(
    "校验和错误（块内定位）",
    [
        {"direction": "send", "data": b64(b"\x05")},
        {"direction": "recv", "data": b64(b"\x06")},
        {"direction": "send", "data": b64(frame(b"P|1", 1, bad_checksum=True))},
    ],
    "CHECKSUM_MISMATCH",
)

bad = bytearray(frame(b"P|1234", 1))
bad[7] ^= 0x01
expect_reject(
    "非原样重传（且重传体跨块）",
    [
        {"direction": "send", "data": b64(b"\x05")},
        {"direction": "recv", "data": b64(b"\x06")},
        {"direction": "send", "data": b64(frame(b"P|1234", 1))},
        {"direction": "recv", "data": b64(b"\x15")},
    ]
    + send_parts(bytes(bad)),
    "NON_IDENTICAL_RETRANSMIT",
)

expect_reject(
    "帧号跳变",
    [
        {"direction": "send", "data": b64(b"\x05")},
        {"direction": "recv", "data": b64(b"\x06")},
        {"direction": "send", "data": b64(frame(b"P|1", 1))},
        {"direction": "recv", "data": b64(b"\x06")},
        {"direction": "send", "data": b64(frame(b"P|2", 4))},
    ],
    "FRAME_NUMBER_JUMP",
)

expect_reject(
    "方向越权（接收方发 ENQ）",
    [{"direction": "recv", "data": b64(b"\x05")}],
    "DIRECTION_VIOLATION",
)

expect_reject(
    "阶段失序（ENQ 前发帧）",
    [{"direction": "send", "data": b64(frame(b"P", 1))}],
    "PHASE_ORDER",
)

expect_reject(
    "不完整结果（缺 EOT，不能被掩盖）",
    [
        {"direction": "send", "data": b64(b"\x05")},
        {"direction": "recv", "data": b64(b"\x06")},
        {"direction": "send", "data": b64(frame(b"P", 1, term=0x03))},
        {"direction": "recv", "data": b64(b"\x06")},
    ],
    "SESSION_INCOMPLETE",
)

expect_reject(
    "重传超限（第 3 次 NAK）",
    (
        [
            {"direction": "send", "data": b64(b"\x05")},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(f1)},
        ]
        + [
            msg
            for _ in range(3)
            for msg in (
                {"direction": "recv", "data": b64(b"\x15")},
                {"direction": "send", "data": b64(f1)},
            )
        ]
    ),
    "RETRANSMIT_LIMIT",
)

print("== 请求校验 ==")
status, body = post([{"direction": "send", "data": "@@@@"}])
check("非法 Base64 → 400", status == 400 and body["error"]["code"] == "INVALID_BASE64", str(body))

req = urllib.request.Request(
    BASE + PATH, data=b"{not json", headers={"Content-Type": "application/json"}, method="POST"
)
try:
    urllib.request.urlopen(req, timeout=5)
    status = 0
except urllib.error.HTTPError as exc:
    status = exc.code
check("非法 JSON → 400", status == 400)

print()
if failures:
    print(f"冒烟失败：{len(failures)} 项 -> {failures}")
    sys.exit(1)
print("全部 API 冒烟通过")

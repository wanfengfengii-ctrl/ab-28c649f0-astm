"""端到端 HTTP API 冒烟测试：在真实套接字上启动服务。"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from app.server import build_server
from tests.test_astm import frame


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def split_bytes(data: bytes, sizes=(2, 1, 3, 1, 2)):
    out, pos, k = [], 0, 0
    while pos < len(data):
        out.append(data[pos : pos + sizes[k % len(sizes)]])
        pos += sizes[k % len(sizes)]
        k += 1
    return out


class ServerHarness:
    def __init__(self):
        self.server = build_server("127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, path: str, payload=None, method="POST"):
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.url(path), data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = ServerHarness().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def post(self, payload):
        return self.harness.request("/api/astm/sessions/audit", payload)

    def test_health(self):
        for _ in range(20):
            status, body = self.harness.request("/health", method="GET")
            if status == 200 and body["status"] == "ok":
                return
            time.sleep(0.05)
        self.fail("健康检查未就绪")

    def test_valid_session_cross_blocks_and_retransmit(self):
        chunks = []
        for part in split_bytes(b"\x05"):
            chunks.append({"direction": "send", "data": b64(part)})
        chunks.append({"direction": "recv", "data": b64(b"\x06")})

        f1 = frame(b"H|\\^&|||LIS", 1)
        for part in split_bytes(f1):  # 帧边界跨块
            chunks.append({"direction": "send", "data": b64(part)})
        chunks.append({"direction": "recv", "data": b64(b"\x15")})  # NAK
        chunks.append({"direction": "send", "data": b64(f1)})      # 原样重传
        chunks.append({"direction": "recv", "data": b64(b"\x06")})

        f2 = frame(b"O|1||^^^GLU|R", 2, term=0x03)
        for part in split_bytes(f2):
            chunks.append({"direction": "send", "data": b64(part)})
        chunks.append({"direction": "recv", "data": b64(b"\x06")})
        chunks.append({"direction": "send", "data": b64(b"\x04")})  # EOT

        status, body = self.post({"sender": "LX-01", "chunks": chunks})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["frame_count"], 2)
        self.assertEqual(body["retransmissions"], 1)
        expected_body = b"H|\\^&|||LISO|1||^^^GLU|R"
        self.assertEqual(body["body"], expected_body.decode("latin-1"))
        self.assertEqual(body["sha256"], hashlib.sha256(expected_body).hexdigest())

    def _reject(self, raw_chunks, code):
        status, body = self.post({"sender": "analyzer-7", "chunks": raw_chunks})
        self.assertEqual(status, 422, body)
        self.assertEqual(body["error"]["code"], code)
        self.assertIn("block_index", body["error"])
        self.assertIn("position", body["error"])
        return body["error"]

    def test_checksum_bad(self):
        chunks = [
            {"direction": "send", "data": b64(b"\x05")},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(frame(b"P|1", 1, bad_checksum=True))},
        ]
        err = self._reject(chunks, "CHECKSUM_MISMATCH")
        self.assertEqual(err["block_index"], 2)
        self.assertEqual(err["position"], 6)

    def test_direction_violation(self):
        self._reject(
            [{"direction": "send", "data": b64(b"\x06")}], "DIRECTION_VIOLATION"
        )

    def test_phase_order(self):
        self._reject(
            [{"direction": "send", "data": b64(frame(b"P", 1))}], "PHASE_ORDER"
        )

    def test_frame_number_jump(self):
        chunks = [
            {"direction": "send", "data": b64(b"\x05")},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(frame(b"P|1", 1))},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(frame(b"P|2", 5))},
        ]
        self._reject(chunks, "FRAME_NUMBER_JUMP")

    def test_non_identical_retransmit_split(self):
        f = frame(b"P|123", 1)
        changed = bytearray(f)
        changed[6] ^= 0x01
        chunks = [
            {"direction": "send", "data": b64(b"\x05")},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(f)},
            {"direction": "recv", "data": b64(b"\x15")},
        ]
        for part in split_bytes(bytes(changed)):
            chunks.append({"direction": "send", "data": b64(part)})
        self._reject(chunks, "NON_IDENTICAL_RETRANSMIT")

    def test_incomplete_session(self):
        chunks = [
            {"direction": "send", "data": b64(b"\x05")},
            {"direction": "recv", "data": b64(b"\x06")},
            {"direction": "send", "data": b64(frame(b"P", 1, term=0x03))},
            {"direction": "recv", "data": b64(b"\x06")},
        ]
        self._reject(chunks, "SESSION_INCOMPLETE")

    def test_bad_request_json(self):
        status, body = self.harness.request(
            "/api/astm/sessions/audit", payload={"sender": "x"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "INVALID_CHUNKS")

    def test_bad_sender(self):
        status, body = self.post({"sender": "", "chunks": []})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "INVALID_SENDER")

    def test_not_found(self):
        status, _ = self.harness.request("/nope", method="GET")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()

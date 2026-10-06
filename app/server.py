"""基于标准库的 ASTM 审计 HTTP 服务。"""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .astm import (
    ProtocolError,
    RequestValidationError,
    audit,
    parse_request,
)

log = logging.getLogger("astm")

_MAX_BODY = 2 * 1024 * 1024  # 1 MiB 原始字节经 Base64 膨胀 + JSON 结构余量


class Handler(BaseHTTPRequestHandler):
    server_version = "ASTMAudit/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        if self.path.rstrip("/") in ("/health", "/api/health"):
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "资源不存在"}})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/api/astm/sessions/audit":
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "资源不存在"}})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length <= 0:
            self._send_json(
                400,
                {"error": {"code": "INVALID_REQUEST", "message": "缺少请求体"}},
            )
            return
        if length > _MAX_BODY:
            self._send_json(
                413,
                {"error": {"code": "PAYLOAD_TOO_LARGE", "message": "请求体过大"}},
            )
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(
                400,
                {"error": {"code": "INVALID_JSON", "message": "请求体不是合法 JSON"}},
            )
            return

        try:
            sender, chunks = parse_request(payload)
            result = audit(chunks)
        except RequestValidationError as exc:
            self._send_json(
                400,
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                    }
                },
            )
            return
        except ProtocolError as exc:
            self._send_json(
                422,
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "block_index": exc.block_index,
                        "position": exc.position,
                    }
                },
            )
            return

        self._send_json(
            200,
            {
                "sender": sender,
                "ok": True,
                "body": result.body.decode("latin-1"),
                "frame_count": result.frame_count,
                "retransmissions": result.retransmissions,
                "sha256": result.sha256,
            },
        )

    def log_message(self, fmt: str, *args: object) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = build_server(host, port)
    log.info("ASTM 审计服务监听 %s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

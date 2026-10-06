#!/usr/bin/env python3
"""容器健康检查：请求本服务 /health。"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

PORT = os.environ.get("PORT", "8080")
URL = f"http://127.0.0.1:{PORT}/health"

try:
    with urllib.request.urlopen(URL, timeout=2) as resp:
        ok = resp.status == 200 and json.loads(resp.read()).get("status") == "ok"
except Exception:
    ok = False

sys.exit(0 if ok else 1)

#!/usr/bin/env python3
"""等待 API 服务健康检查通过。"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
DEADLINE = time.time() + float(os.environ.get("HEALTH_TIMEOUT", "60"))

while True:
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=2) as resp:
            body = json.loads(resp.read())
            if resp.status == 200 and body.get("status") == "ok":
                print(f"API 已就绪：{BASE}")
                break
    except (OSError, urllib.error.URLError):
        pass
    if time.time() > DEADLINE:
        print(f"等待 {BASE} 健康检查超时", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.5)

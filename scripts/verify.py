#!/usr/bin/env python3
"""一次性 verify 服务入口：

1. 代码测试（unittest）
2. 构建检查（py_compile 全量字节码编译）
3. 等待 api 服务健康
4. 含跨块切分与重传的 API 冒烟

全部通过后以 0 退出，否则非零退出（容器随即退出）。
"""

from __future__ import annotations

import os
import py_compile
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def step(title: str) -> None:
    print(f"\n===== {title} =====", flush=True)


def run(cmd: list[str]) -> int:
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT).returncode


def main() -> int:
    step("1/4 代码测试：unittest")
    if run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]):
        print("单元测试失败", file=sys.stderr)
        return 1

    step("2/4 构建检查：py_compile")
    failed = []
    for path in ROOT.rglob("*.py"):
        if any(part in (".venv", "venv", "__pycache__") for part in path.parts):
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError:
            failed.append(str(path.relative_to(ROOT)))
    if failed:
        print("字节码编译失败：" + ", ".join(failed), file=sys.stderr)
        return 1
    print(f"已编译 {sum(1 for _ in ROOT.rglob('*.py'))} 个文件")

    step("3/4 等待 API 健康检查")
    if run([sys.executable, str(ROOT / "scripts" / "wait_health.py")]):
        return 1

    step("4/4 API 冒烟（跨块 + 重传 + 拒绝路径）")
    if run([sys.executable, str(ROOT / "scripts" / "smoke_api.py")]):
        return 1

    print("\nVERIFY 全部通过", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

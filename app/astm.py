"""ASTM E1381/E1394 风格会话审计引擎。

输入为按捕获顺序排列的方向化字节块（块可在任意位置切分），引擎将其视为一条
连续字节流并严格重放：

* 发送方依次完成 ``ENQ`` → 逐帧发送 → ``EOT``；
* 接收方只能回复 ``ACK`` / ``NAK``；
* 帧号 1..7、0 循环；``NAK`` 后只能原样重传当前帧，且至多两次；
* 帧格式 ``STX FN 正文(1..240) ETB/ETX CS CS CR LF``，FN 为单个 0-7 数字，
  校验和为 FN、正文、结束符逐字节求和模 256 的两位大写十六进制。

任何违规都抛出 :class:`ProtocolError`，携带稳定错误码以及首个出错块内的位置。
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import re
from dataclasses import dataclass

# ---- ASTM 控制字符 -------------------------------------------------------
STX = 0x02
ETX = 0x03
ETB = 0x17
ENQ = 0x05
ACK = 0x06
NAK = 0x15
EOT = 0x04
CR = 0x0D
LF = 0x0A

MAX_CHUNKS = 2000
MAX_TOTAL_BYTES = 1024 * 1024  # 1 MiB
MAX_FRAME_DATA = 240
MAX_RETRANSMITS = 2

_HEX_DIGITS = set(b"0123456789ABCDEF")
_SENDER_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$", re.ASCII)

# 接收方允许发送的全部字节
_RECEIVER_BYTES = frozenset((ACK, NAK))


class RequestValidationError(ValueError):
    """请求本身格式不合法（与协议重放无关）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ProtocolError(Exception):
    """字节流违反 ASTM 会话规则。"""

    def __init__(self, code: str, message: str, block_index: int, position: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.block_index = block_index
        self.position = position


@dataclass(frozen=True)
class Chunk:
    direction: str  # "send"（发送方→接收方）或 "recv"（接收方→发送方）
    data: bytes


@dataclass(frozen=True)
class AuditResult:
    body: bytes
    frame_count: int
    retransmissions: int
    sha256: str


def _is_text_byte(b: int) -> bool:
    # 可打印 ASCII（0x20-0x7E），另允许 ASTM 记录内部使用的 CR。
    return 0x20 <= b <= 0x7E or b == CR


def parse_request(payload: object) -> tuple[str, list[Chunk]]:
    """解析并校验 JSON 请求体，返回 sender 与解码后的块列表。"""
    if not isinstance(payload, dict):
        raise RequestValidationError("INVALID_REQUEST", "请求体必须为 JSON 对象")

    sender = payload.get("sender")
    if not isinstance(sender, str) or not _SENDER_RE.match(sender):
        raise RequestValidationError(
            "INVALID_SENDER",
            "sender 必须为 1-128 个字符，仅限字母、数字及 . _ : -",
        )

    raw_chunks = payload.get("chunks")
    if not isinstance(raw_chunks, list) or not raw_chunks:
        raise RequestValidationError("INVALID_CHUNKS", "chunks 必须为非空数组")
    if len(raw_chunks) > MAX_CHUNKS:
        raise RequestValidationError(
            "TOO_MANY_CHUNKS", f"chunks 数量不得超过 {MAX_CHUNKS}"
        )

    chunks: list[Chunk] = []
    total = 0
    for idx, item in enumerate(raw_chunks):
        if not isinstance(item, dict):
            raise RequestValidationError(
                "INVALID_CHUNK", f"第 {idx} 块必须为对象"
            )
        direction = item.get("direction")
        if direction not in ("send", "recv"):
            raise RequestValidationError(
                "INVALID_DIRECTION",
                f"第 {idx} 块 direction 必须为 send 或 recv",
            )
        encoded = item.get("data")
        if not isinstance(encoded, str):
            raise RequestValidationError(
                "INVALID_BASE64", f"第 {idx} 块 data 必须为 Base64 字符串"
            )
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:  # binascii.Error 等
            raise RequestValidationError(
                "INVALID_BASE64", f"第 {idx} 块不是合法的标准 Base64"
            ) from exc
        if not data:
            raise RequestValidationError(
                "INVALID_CHUNK", f"第 {idx} 块解码后为空"
            )
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise RequestValidationError(
                "PAYLOAD_TOO_LARGE",
                f"解码后总字节数不得超过 {MAX_TOTAL_BYTES} 字节 (1 MiB)",
            )
        chunks.append(Chunk(direction=direction, data=data))

    return sender, chunks


def audit(chunks: list[Chunk]) -> AuditResult:
    """对解码后的字节块执行完整会话审计。"""

    ends: list[int] = []
    dirs: list[str] = []
    stream = bytearray()
    total = 0
    for chunk in chunks:
        total += len(chunk.data)
        ends.append(total)
        dirs.append(chunk.direction)
        stream.extend(chunk.data)

    if total > MAX_TOTAL_BYTES:
        raise RequestValidationError(
            "PAYLOAD_TOO_LARGE",
            f"解码后总字节数不得超过 {MAX_TOTAL_BYTES} 字节 (1 MiB)",
        )

    def locate(pos: int) -> tuple[int, int]:
        """把流内全局偏移换算成 (块下标, 块内偏移)。"""
        if not ends:
            return 0, 0
        if pos >= total:
            # EOF 类错误：定位到最后一个块的末尾（越界一位）。
            start = ends[-2] if len(ends) > 1 else 0
            return len(ends) - 1, total - start
        idx = bisect.bisect_right(ends, pos)
        start = ends[idx - 1] if idx > 0 else 0
        return idx, pos - start

    def fail(code: str, pos: int, message: str) -> None:
        block_index, position = locate(pos)
        raise ProtocolError(code, message, block_index, position)

    def direction_at(pos: int) -> str:
        idx = bisect.bisect_right(ends, pos)
        if idx >= len(dirs):
            idx = len(dirs) - 1
        return dirs[idx]

    # 会话状态
    S_ENQ = "ENQ"                      # 等待发送方 ENQ
    S_WAIT_ENQ_ACK = "WAIT_ENQ_ACK"    # ENQ 已发，等待 ACK/NAK
    S_FRAME = "FRAME"                  # 等待新帧 STX
    S_FSCAN = "FSCAN"                  # 正在逐字节接收帧
    S_RETRY = "RETRY"                  # NAK 后等待原样重传
    S_WAIT_FRAME_ACK = "WAIT_FRAME_ACK"
    S_EXPECT_EOT = "EXPECT_EOT"
    S_DONE = "DONE"

    state = S_ENQ
    expected_fn = 1
    retries_left = MAX_RETRANSMITS
    retransmissions = 0
    frame_count = 0
    body = bytearray()

    # 帧解析临时量
    fstate = ""
    frame_start = 0
    fn_pos = 0
    cs_pos = 0
    fn1 = 0
    fcsum = 0
    fdata = bytearray()
    fraw = bytearray()
    term = 0
    pending_raw = b""
    pending_term = 0
    retry_j = 0

    i = 0
    while i < total:
        b = stream[i]
        direction = direction_at(i)

        # ---- 方向越权统一前置判定 -------------------------------------
        if direction == "recv":
            if b not in _RECEIVER_BYTES:
                fail(
                    "DIRECTION_VIOLATION",
                    i,
                    "接收方只能发送 ACK 或 NAK",
                )
        else:
            if b in _RECEIVER_BYTES:
                fail(
                    "DIRECTION_VIOLATION",
                    i,
                    "ACK/NAK 只能由接收方发送",
                )

        # ---- ENQ：等待发送方发起会话 ----------------------------------
        if state == S_ENQ:
            if direction == "recv":
                fail("PHASE_ORDER", i, "ENQ 之前不允许接收方回复")
            if b == ENQ:
                state = S_WAIT_ENQ_ACK
            elif b == STX:
                fail("PHASE_ORDER", i, "ENQ 之前不允许发送帧")
            elif b == EOT:
                fail("PHASE_ORDER", i, "会话尚未建立，收到 EOT")
            else:
                fail("PHASE_ORDER", i, "会话必须以发送方 ENQ 开始")

        # ---- ENQ 之后等待 ACK（NAK 允许重新 ENQ） ---------------------
        elif state == S_WAIT_ENQ_ACK:
            if direction == "send":
                fail("PHASE_ORDER", i, "ENQ 之后必须等待接收方 ACK/NAK")
            if b == ACK:
                state = S_FRAME
                expected_fn = 1
            else:  # NAK：回到握手起点，允许再次 ENQ
                state = S_ENQ

        # ---- 等待新帧 --------------------------------------------------
        elif state == S_FRAME:
            if direction == "recv":
                fail("PHASE_ORDER", i, "当前阶段应发送帧，收到接收方 ACK/NAK")
            if b == STX:
                frame_start = i
                fn_pos = 0
                cs_pos = 0
                fn1 = 0
                fcsum = 0
                fdata = bytearray()
                fraw = bytearray([STX])
                fstate = "FN"
                state = S_FSCAN
            elif b == EOT:
                fail("PHASE_ORDER", i, "至少需要一帧且末帧为 ETX 后才能 EOT")
            elif b == ENQ:
                fail("PHASE_ORDER", i, "帧传输阶段不允许重新 ENQ")
            else:
                fail("UNEXPECTED_BYTE", i, "帧必须以 STX 开始")

        # ---- NAK 后原样重传 --------------------------------------------
        elif state == S_RETRY:
            if direction == "recv":
                fail("PHASE_ORDER", i, "NAK 后发送方必须重传当前帧")
            expected = pending_raw[retry_j]
            if b != expected:
                fail(
                    "NON_IDENTICAL_RETRANSMIT",
                    i,
                    "NAK 后必须逐字节原样重传当前帧",
                )
            retry_j += 1
            if retry_j == len(pending_raw):
                retransmissions += 1
                state = S_WAIT_FRAME_ACK

        # ---- 帧内逐字节解析 --------------------------------------------
        elif state == S_FSCAN:
            if direction == "recv":
                fail("PHASE_ORDER", i, "帧传输未完成，收到接收方 ACK/NAK")

            if fstate == "FN":
                if 0x30 <= b <= 0x37:
                    fn_pos = i
                    fn1 = b
                    fcsum += b
                    fraw.append(b)
                    fstate = "DATA"
                else:
                    fail("FRAME_FORMAT", frame_start, "STX 后必须为单个帧号数字 0-7")

            elif fstate == "DATA":
                if b in (ETB, ETX):
                    if not fdata:
                        fail("FRAME_EMPTY", frame_start, "帧正文长度必须为 1-240 字节")
                    fcsum += b
                    fraw.append(b)
                    term = b
                    cs_pos = i + 1
                    fstate = "CS1"
                else:
                    if len(fdata) >= MAX_FRAME_DATA:
                        fail(
                            "FRAME_TOO_LONG",
                            i,
                            f"帧正文不得超过 {MAX_FRAME_DATA} 字节",
                        )
                    if not _is_text_byte(b):
                        fail("PAYLOAD_NOT_TEXT", i, "正文包含不允许的 ASTM 文本字节")
                    fcsum += b
                    fdata.append(b)
                    fraw.append(b)

            elif fstate == "CS1":
                if b not in _HEX_DIGITS:
                    fail("CHECKSUM_FORMAT", cs_pos, "校验和必须为两位大写十六进制")
                cs_hi = b
                fraw.append(b)
                fstate = "CS2"

            elif fstate == "CS2":
                if b not in _HEX_DIGITS:
                    fail("CHECKSUM_FORMAT", cs_pos, "校验和必须为两位大写十六进制")
                fraw.append(b)
                actual = int(chr(cs_hi) + chr(b), 16)
                if actual != (fcsum & 0xFF):
                    fail(
                        "CHECKSUM_MISMATCH",
                        cs_pos,
                        f"校验和错误：帧为 {fcsum & 0xFF:02X}，报文为 {actual:02X}",
                    )
                fstate = "CR"

            elif fstate == "CR":
                fraw.append(b)
                if b != CR:
                    fail("FRAME_TERMINATOR", i, "校验和之后必须为 CRLF")
                fstate = "LF"

            else:  # LF
                fraw.append(b)
                if b != LF:
                    fail("FRAME_TERMINATOR", i, "校验和之后必须为 CRLF")
                # 整帧接收完成
                fn = fn1 - 0x30
                if fn != expected_fn:
                    fail(
                        "FRAME_NUMBER_JUMP",
                        fn_pos,
                        f"帧号跳变：期望 {expected_fn}，实际 {fn}",
                    )
                frame_count += 1
                body.extend(fdata)
                pending_raw = bytes(fraw)
                pending_term = term
                retries_left = MAX_RETRANSMITS
                state = S_WAIT_FRAME_ACK

        # ---- 帧已收齐，等待接收方裁决 ----------------------------------
        elif state == S_WAIT_FRAME_ACK:
            if direction == "send":
                fail("PHASE_ORDER", i, "帧发送后必须等待接收方 ACK/NAK")
            if b == ACK:
                if pending_term == ETX:
                    state = S_EXPECT_EOT
                else:
                    expected_fn = (expected_fn + 1) & 0x07
                    state = S_FRAME
            else:  # NAK
                if retries_left == 0:
                    fail(
                        "RETRANSMIT_LIMIT",
                        i,
                        f"同一帧最多重传 {MAX_RETRANSMITS} 次",
                    )
                retries_left -= 1
                retry_j = 0
                state = S_RETRY

        # ---- 末帧 ACK 后等待 EOT ---------------------------------------
        elif state == S_EXPECT_EOT:
            if direction == "recv":
                fail("PHASE_ORDER", i, "末帧已确认，接收方不应再回复")
            if b == EOT:
                state = S_DONE
            elif b == STX:
                fail("PHASE_ORDER", i, "ETX 末帧之后不允许再发送帧")
            elif b == ENQ:
                fail("PHASE_ORDER", i, "ETX 末帧之后不允许重新 ENQ")
            else:
                fail("PHASE_ORDER", i, "当前阶段只能由发送方发送 EOT")

        # ---- EOT 之后流必须结束 ----------------------------------------
        elif state == S_DONE:
            fail("TRAILING_DATA", i, "EOT 之后不允许再有任何字节")

        i += 1

    # ---- 流结束时的完整性判定 --------------------------------------------
    if state == S_DONE:
        digest = hashlib.sha256(body).hexdigest()
        return AuditResult(
            body=bytes(body),
            frame_count=frame_count,
            retransmissions=retransmissions,
            sha256=digest,
        )

    if state in (S_FSCAN, S_RETRY):
        fail("INCOMPLETE_FRAME", total, "流结束时帧不完整")
    if state == S_WAIT_FRAME_ACK:
        fail("SESSION_INCOMPLETE", total, "帧后缺少接收方 ACK/NAK")
    fail("SESSION_INCOMPLETE", total, "流结束时会话未以 EOT 正常关闭")
    raise AssertionError("unreachable")

"""ASTM 审计引擎单元测试。"""

from __future__ import annotations

import base64
import hashlib
import random
import unittest

from app.astm import (
    ACK,
    CR,
    ENQ,
    EOT,
    ETB,
    ETX,
    LF,
    NAK,
    STX,
    Chunk,
    ProtocolError,
    RequestValidationError,
    audit,
    parse_request,
)


def frame(data: bytes, fn: int, term: int = ETB, *, bad_checksum: bool = False) -> bytes:
    digit = ord(str(fn))
    tail = bytes((digit,)) + data + bytes((term,))
    cs = sum(tail) & 0xFF
    if bad_checksum:
        cs ^= 0xFF
    return bytes((STX,)) + tail + f"{cs:02X}".encode("ascii") + bytes((CR, LF))


class Builder:
    """按捕获顺序收集方向化事件，并可把每个事件再任意切成小块。"""

    def __init__(self, split_sizes=(1, 3, 2, 5, 1, 4)):
        self.events: list[tuple[str, bytes]] = []
        self.split_sizes = split_sizes

    def add(self, direction: str, data: bytes) -> "Builder":
        self.events.append((direction, data))
        return self

    def send(self, data: bytes) -> "Builder":
        return self.add("send", data)

    def recv(self, data: bytes) -> "Builder":
        return self.add("recv", data)

    def handshake(self, nak_first: bool = False) -> "Builder":
        self.send(bytes((ENQ,)))
        if nak_first:
            self.recv(bytes((NAK,)))
            self.send(bytes((ENQ,)))
        self.recv(bytes((ACK,)))
        return self

    def eot(self) -> "Builder":
        return self.send(bytes((EOT,)))

    def chunks(self, split: bool = False) -> list[Chunk]:
        out: list[Chunk] = []
        sizes = list(self.split_sizes)
        for direction, data in self.events:
            if not split:
                out.append(Chunk(direction, data))
                continue
            pos = 0
            k = 0
            while pos < len(data):
                size = sizes[k % len(sizes)]
                k += 1
                out.append(Chunk(direction, data[pos : pos + size]))
                pos += size
        return out

    def run(self, split: bool = False):
        return audit(self.chunks(split))


def valid_session(nak_first: bool = False, retransmits: int = 0) -> Builder:
    b = Builder().handshake(nak_first=nak_first)
    f = frame(b"P|1|ABC", 1)
    b.send(f)
    for _ in range(retransmits):
        b.recv(bytes((NAK,)))
        b.send(f)
    b.recv(bytes((ACK,)))
    b.send(frame(b"R|1|OK", 2, term=ETX))
    b.recv(bytes((ACK,)))
    b.eot()
    return b


class ValidSessionTests(unittest.TestCase):
    def test_single_path(self):
        res = valid_session().run()
        self.assertEqual(res.body, b"P|1|ABCR|1|OK")
        self.assertEqual(res.frame_count, 2)
        self.assertEqual(res.retransmissions, 0)
        self.assertEqual(res.sha256, hashlib.sha256(res.body).hexdigest())

    def test_split_across_blocks(self):
        # 块边界落在 STX、帧号、校验和、CRLF 内部。
        res = valid_session(retransmits=1).run(split=True)
        self.assertEqual(res.frame_count, 2)
        self.assertEqual(res.retransmissions, 1)

    def test_random_splits(self):
        rng = random.Random(42)
        b = valid_session(retransmits=2)
        chunks = []
        for direction, data in b.events:
            cuts = [0]
            while cuts[-1] < len(data):
                cuts.append(min(len(data), cuts[-1] + rng.randint(1, 4)))
            for a, z in zip(cuts, cuts[1:]):
                chunks.append(Chunk(direction, data[a:z]))
        res = audit(chunks)
        self.assertEqual(res.retransmissions, 2)
        self.assertEqual(res.frame_count, 2)

    def test_frame_number_wrap(self):
        b = Builder().handshake()
        payloads = []
        for n in range(9):  # 帧号 1..7,0,1
            fn = (n + 1) & 0x07
            term = ETX if n == 8 else ETB
            payload = f"frame-{n}".encode()
            payloads.append(payload)
            b.send(frame(payload, fn, term=term))
            b.recv(bytes((ACK,)))
        b.eot()
        res = b.run(split=True)
        self.assertEqual(res.frame_count, 9)
        self.assertEqual(res.body, b"".join(payloads))

    def test_enq_nak_then_retry_enq(self):
        res = valid_session(nak_first=True).run()
        self.assertEqual(res.frame_count, 2)

    def test_data_length_boundaries(self):
        b = Builder().handshake()
        data = b"X" * 240
        b.send(frame(data, 1, term=ETX))
        b.recv(bytes((ACK,)))
        b.eot()
        res = b.run()
        self.assertEqual(len(res.body), 240)

    def test_cr_inside_body(self):
        b = Builder().handshake()
        b.send(frame(b"H|1\rO|2", 1, term=ETX))
        b.recv(bytes((ACK,)))
        b.eot()
        res = b.run(split=True)
        self.assertEqual(res.body, b"H|1\rO|2")


class RejectTests(unittest.TestCase):
    def assertReject(self, builder: Builder, code: str, split: bool = False):
        try:
            audit(builder.chunks(split))
        except ProtocolError as exc:
            self.assertEqual(exc.code, code)
            return exc
        self.fail(f"应当拒绝并返回 {code}")

    def test_checksum_mismatch_and_location(self):
        chunks = [
            Chunk("send", bytes((ENQ,))),
            Chunk("recv", bytes((ACK,))),
            Chunk("send", frame(b"P|1", 1, bad_checksum=True)),
        ]
        with self.assertRaises(ProtocolError) as ctx:
            audit(chunks)
        self.assertEqual(ctx.exception.code, "CHECKSUM_MISMATCH")
        # 块 2：STX + 帧号 + 3 字节正文 + 结束符，校验和起始偏移 6
        self.assertEqual(ctx.exception.block_index, 2)
        self.assertEqual(ctx.exception.position, 6)

    def test_checksum_split_location_stable(self):
        f = frame(b"P|1", 1, bad_checksum=True)
        b = Builder().handshake()
        b.send(f)
        chunks = b.chunks(split=True)
        exc = self.assertReject(b, "CHECKSUM_MISMATCH", split=True)
        # 位置必须落在报告块内且指向该校验和首字节
        self.assertLess(exc.position, len(chunks[exc.block_index].data))
        self.assertEqual(chunks[exc.block_index].data[exc.position], f[-4])

    def test_lowercase_checksum_rejected(self):
        # b"w" 时校验和为 AB（含字母），小写化后必然触发格式错误
        f = frame(b"w", 1)
        f = f[:-4] + f[-4:-2].lower() + f[-2:]
        b = Builder().handshake().send(f)
        self.assertReject(b, "CHECKSUM_FORMAT")

    def test_frame_number_jump(self):
        b = Builder().handshake()
        b.send(frame(b"P|1", 1)).recv(bytes((ACK,)))
        b.send(frame(b"P|2", 3))  # 期望 2
        self.assertReject(b, "FRAME_NUMBER_JUMP")

    def test_non_identical_retransmit(self):
        f = frame(b"P|1", 1)
        b = Builder().handshake().send(f).recv(bytes((NAK,)))
        changed = bytearray(f)
        changed[5] ^= 0x01  # 篡改正文中的一个字节
        b.send(bytes(changed))
        self.assertReject(b, "NON_IDENTICAL_RETRANSMIT", split=True)

    def test_three_naks_exceed_limit(self):
        f = frame(b"P|1", 1)
        b = Builder().handshake().send(f)
        for _ in range(3):
            b.recv(bytes((NAK,))).send(f)
        self.assertReject(b, "RETRANSMIT_LIMIT")

    def test_two_retransmits_allowed(self):
        f = frame(b"P|1", 1, term=ETX)
        b = Builder().handshake().send(f)
        for _ in range(2):
            b.recv(bytes((NAK,))).send(f)
        b.recv(bytes((ACK,))).eot()
        self.assertEqual(b.run().retransmissions, 2)

    def test_frame_before_enq(self):
        b = Builder().send(frame(b"P|1", 1))
        self.assertReject(b, "PHASE_ORDER")

    def test_eot_without_frame(self):
        b = Builder().handshake().eot()
        self.assertReject(b, "PHASE_ORDER")

    def test_frame_after_etx(self):
        b = Builder().handshake()
        b.send(frame(b"P|1", 1, term=ETX)).recv(bytes((ACK,)))
        b.send(frame(b"X", 2))
        self.assertReject(b, "PHASE_ORDER")

    def test_trailing_after_eot(self):
        b = valid_session()
        b.add("send", b"Z")
        self.assertReject(b, "TRAILING_DATA")

    def test_missing_eot(self):
        b = Builder().handshake()
        b.send(frame(b"P|1", 1, term=ETX)).recv(bytes((ACK,)))
        self.assertReject(b, "SESSION_INCOMPLETE")

    def test_missing_ack_after_frame(self):
        b = Builder().handshake()
        b.send(frame(b"P|1", 1))
        self.assertReject(b, "SESSION_INCOMPLETE", split=True)

    def test_truncated_frame(self):
        b = Builder().handshake()
        f = frame(b"P|1", 1)
        b.send(f[:-3])  # 截掉 CRLF 与一位校验和
        self.assertReject(b, "INCOMPLETE_FRAME")

    def test_empty_body(self):
        b = Builder().handshake()
        b.send(bytes((STX, ord("1"), ETX)))
        self.assertReject(b, "FRAME_EMPTY")

    def test_body_too_long(self):
        b = Builder().handshake()
        b.send(frame(b"X" * 241, 1))
        self.assertReject(b, "FRAME_TOO_LONG")

    def test_non_text_byte(self):
        b = Builder().handshake()
        b.send(frame(b"A\x01B", 1))
        self.assertReject(b, "PAYLOAD_NOT_TEXT")

    def test_sender_direction_violation(self):
        # 发送方发出 ACK
        b = Builder().send(bytes((ENQ,))).send(bytes((ACK,)))
        self.assertReject(b, "DIRECTION_VIOLATION")

    def test_receiver_direction_violation(self):
        # 接收方发出 ENQ；接收方发出其他字节
        self.assertReject(Builder().add("recv", bytes((ENQ,))), "DIRECTION_VIOLATION")
        self.assertReject(
            Builder().send(bytes((ENQ,))).add("recv", b"X"), "DIRECTION_VIOLATION"
        )

    def test_receiver_unsolicited(self):
        b = Builder().add("recv", bytes((ACK,)))
        self.assertReject(b, "PHASE_ORDER")

    def test_ack_expected_after_enq(self):
        b = Builder().send(bytes((ENQ,))).send(frame(b"P|1", 1))
        self.assertReject(b, "PHASE_ORDER")

    def test_missing_crlf(self):
        f = frame(b"P|1", 1)[:-2]
        b = Builder().handshake().send(f)
        self.assertReject(b, "INCOMPLETE_FRAME")


class RequestParsingTests(unittest.TestCase):
    def req(self, sender="LX-01", chunks=None):
        if chunks is None:
            chunks = [{"direction": "send", "data": base64.b64encode(b"x").decode()}]
        return {"sender": sender, "chunks": chunks}

    def test_valid(self):
        sender, chunks = parse_request(self.req())
        self.assertEqual(sender, "LX-01")
        self.assertEqual(chunks[0].data, b"x")

    def test_bad_sender(self):
        for bad in ("", "a b", "中文", "a/b", 123):
            with self.assertRaises(RequestValidationError) as ctx:
                parse_request(self.req(sender=bad))
            self.assertEqual(ctx.exception.code, "INVALID_SENDER")

    def test_bad_base64(self):
        with self.assertRaises(RequestValidationError) as ctx:
            parse_request(self.req(chunks=[{"direction": "send", "data": "@@@"}]))
        self.assertEqual(ctx.exception.code, "INVALID_BASE64")

    def test_empty_chunk(self):
        with self.assertRaises(RequestValidationError) as ctx:
            parse_request(self.req(chunks=[{"direction": "send", "data": ""}]))
        self.assertEqual(ctx.exception.code, "INVALID_CHUNK")

    def test_bad_direction(self):
        with self.assertRaises(RequestValidationError) as ctx:
            parse_request(
                self.req(chunks=[{"direction": "west", "data": "eA=="}])
            )
        self.assertEqual(ctx.exception.code, "INVALID_DIRECTION")

    def test_too_many_chunks(self):
        chunks = [
            {"direction": "send", "data": base64.b64encode(b"x").decode()}
            for _ in range(2001)
        ]
        with self.assertRaises(RequestValidationError) as ctx:
            parse_request(self.req(chunks=chunks))
        self.assertEqual(ctx.exception.code, "TOO_MANY_CHUNKS")

    def test_too_large(self):
        big = base64.b64encode(b"x" * (1024 * 1024 + 1)).decode()
        with self.assertRaises(RequestValidationError) as ctx:
            parse_request(self.req(chunks=[{"direction": "send", "data": big}]))
        self.assertEqual(ctx.exception.code, "PAYLOAD_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()

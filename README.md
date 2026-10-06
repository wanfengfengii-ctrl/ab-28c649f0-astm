# ASTM 会话审计服务

检验中心用于复核分析仪（sender）与主机之间 ASTM 文本传输的审计接口。调用方提交
按捕获顺序排列的、带方向的 Base64 字节块（块边界可落在任意控制字节或数据帧内部），
服务将其重组为连续字节流并严格重放整段会话，避免采集分块或重传掩盖不完整结果。

零第三方依赖，仅使用 Python 3.11 标准库。

## 协议规则

* 发送方依次完成：`ENQ` → 逐帧发送 → `EOT`；
* 接收方只能回复 `ACK` 或 `NAK`；
* 帧格式：`STX FN 正文 ETB/ETX CS CS CR LF`
  * `FN`：单个帧号数字，按 1→2→…→7→0→1 循环；
  * 正文：1–240 个可打印 ASTM 文本字节（`0x20–0x7E`，另允许记录内 `CR`）；
  * `ETB` 表示后续还有帧，最后一帧必须以 `ETX` 结束；
  * 校验和：`STX` 之后至结束符（含帧号、正文、`ETB/ETX`）逐字节求和模 256，
    两位**大写**十六进制；其后必须为 `CRLF`；
* `ENQ` 收到 `NAK` 后允许重新 `ENQ`；
* 帧收到 `NAK` 后只能**逐字节原样**重传当前帧，同一帧至多重传 2 次
  （即最多 3 次 `NAK` 拒绝）。

## 启动（Docker Compose）

```bash
# 宿主机端口可配置（默认 8080）
HOST_PORT=18080 docker compose up --build
```

* `api`：常驻审计服务，带容器健康检查；
* `verify`：一次性服务，等待 `api` 健康后自动执行
  单元测试 → 构建检查 → API 冒烟（含跨块与重传），以退出码报告结果后自行退出：

```bash
docker compose run --rm verify   # 单独运行
docker compose logs verify       # 查看结果
```

## 本地运行（无 Docker）

```bash
python -m app.server                      # 默认 :8080，PORT 可配置
python -m unittest discover -s tests      # 全部测试
PORT=8080 python -m app.server &          # 完整 verify 流程
python scripts/verify.py
```

## API

### `GET /health`

```json
{"status": "ok"}
```

### `POST /api/astm/sessions/audit`

请求：

* `sender`：1–128 字符，`A-Z a-z 0-9 . _ : -`；
* `chunks`：1–2000 个块，按捕获顺序排列；
  * `direction`：`send`（发送方→接收方）或 `recv`（接收方→发送方）；
  * `data`：标准 Base64；解码总量 ≤ 1 MiB；块不能为空，边界可任意切分。

合法会话响应 `200`：

```json
{
  "sender": "CHEM-1",
  "ok": true,
  "body": "H|...O|...R|...",
  "frame_count": 3,
  "retransmissions": 1,
  "sha256": "…"
}
```

`body` 为所有帧正文按序拼接（重传帧只计一次）；`sha256` 为重组正文原始字节的
SHA-256。

违规响应 `422`（请求本身格式问题为 `400`），错误码稳定，并给出首个出错块
（`block_index` 从 0 开始）及块内偏移（`position` 从 0 开始；EOF 类错误指向
最后一个块末尾越界一位）：

```json
{
  "error": {
    "code": "CHECKSUM_MISMATCH",
    "message": "校验和错误：帧为 9E，报文为 9F",
    "block_index": 2,
    "position": 6
  }
}
```

错误码：

| code | 含义 |
| --- | --- |
| `DIRECTION_VIOLATION` | 方向越权（发送方发 ACK/NAK，或接收方发其它字节） |
| `PHASE_ORDER` | 阶段失序（ENQ 前发帧、未确认即发下一帧、ETX 后再发帧、缺 EOT 时机错误等） |
| `FRAME_NUMBER_JUMP` | 帧号未按 1..7、0 循环 |
| `NON_IDENTICAL_RETRANSMIT` | NAK 后未逐字节原样重传 |
| `RETRANSMIT_LIMIT` | 同一帧重传超过 2 次 |
| `CHECKSUM_MISMATCH` | 校验和计算不符 |
| `CHECKSUM_FORMAT` | 校验和不是两位大写十六进制 |
| `FRAME_FORMAT` / `FRAME_EMPTY` / `FRAME_TOO_LONG` | 帧结构/正文长度错误 |
| `PAYLOAD_NOT_TEXT` | 正文含非允许文本字节 |
| `FRAME_TERMINATOR` | 校验和后不是 CRLF |
| `INCOMPLETE_FRAME` | 流结束时帧不完整 |
| `SESSION_INCOMPLETE` | 流结束时会话未正常完成（如缺 ACK/EOT） |
| `TRAILING_DATA` | EOT 之后仍有字节 |
| `UNEXPECTED_BYTE` | 帧未以 STX 开始 |
| `INVALID_SENDER` / `INVALID_CHUNKS` / `INVALID_CHUNK` / `INVALID_DIRECTION` / `INVALID_BASE64` / `INVALID_JSON` / `INVALID_REQUEST` | 请求校验错误（400） |
| `TOO_MANY_CHUNKS` / `PAYLOAD_TOO_LARGE` | 超过块数或 1 MiB 总量限制 |

## 示例

```bash
curl -s http://localhost:8080/api/astm/sessions/audit \
  -H 'Content-Type: application/json' \
  -d '{"sender":"LX-01","chunks":[
    {"direction":"send","data":"BQ=="},
    {"direction":"recv","data":"Bg=="},
    {"direction":"send","data":"AjExfDEDMTINCg=="},
    {"direction":"recv","data":"Bg=="},
    {"direction":"send","data":"BA=="}
  ]}'
```

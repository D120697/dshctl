#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dshctl —— 让 DSH 操作自己的一套工具。

它通过正在运行的 DSH 桌面实例**自己的** /api Remote 网关工作：签名 cookie 认证、
JSON-RPC 风格信封、session/* 方法，全程不需要模拟点击，也不需要重启 DSH。

快速开始（在任意工作区目录下执行）：

    python dshctl.py instances                 # 找到正在跑的 DSH 实例
    python dshctl.py ask "定时任务"             # 在当前工作区新建会话并发送
    python dshctl.py sessions                  # 列出会话
    python dshctl.py memory <sessionId>        # 看这个会话注入了哪些记忆

设计要点：
  * 端口自动发现——DSH 每次重启端口会变（63195 → 49890），不接受硬编码。
  * 会话归属跟随发起目录——不传 --cwd 时用当前工作目录创建会话，
    这样新会话和发起它的工作区是同一个。
  * 只读优先——除 new/send/ask 外都不改 DSH 状态。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HOME = os.environ.get("DSH_HOME") or os.path.join(os.path.expanduser("~"), ".dsh")
SESSIONS_DIR = os.path.join(HOME, "sessions")
CREDENTIALS = os.path.join(HOME, ".credentials.yaml")
DEFAULT_TIMEOUT = 120


# ── 输出 ────────────────────────────────────────────────────────────────
def out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def emit_json(value) -> None:
    out(json.dumps(value, ensure_ascii=False, indent=2, default=str))


# ── 实例发现 ────────────────────────────────────────────────────────────
def _dsh_pids() -> set[int]:
    """正在运行的 DeepSeek Harness 进程号。"""
    pids: set[int] = set()
    try:
        raw = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq DeepSeek Harness.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=20, errors="replace",
        ).stdout
    except Exception:
        return pids
    for line in raw.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            pids.add(int(parts[1]))
    return pids


def _listening_ports(pids: set[int]) -> list[int]:
    ports: set[int] = set()
    try:
        raw = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=30, errors="replace").stdout
    except Exception:
        return []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].upper() != "TCP" or fields[3].upper() != "LISTENING":
            continue
        local, pid = fields[1], fields[4]
        if not pid.isdigit() or int(pid) not in pids:
            continue
        host, _, port = local.rpartition(":")
        if host not in ("127.0.0.1", "localhost"):
            continue
        if port.isdigit():
            ports.add(int(port))
    return sorted(ports)


def _api_alive(port: int, timeout: float = 2.0) -> bool:
    """DSH 的 API 端口对无凭据请求回 401；用这个指纹认端口，避免误判其它服务。"""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/session/list",
        data=b'{"type":"client-request","rpcId":"probe","method":"session/list","payload":{"args":{"_request":{}}}}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 401, 403)
    except urllib.error.HTTPError as err:
        return err.code in (401, 403)
    except Exception:
        return False


def discover_instances(verbose: bool = False) -> list[int]:
    pids = _dsh_pids()
    if verbose:
        out(f"# DSH 进程: {sorted(pids) or '无'}")
    ports = _listening_ports(pids)
    if verbose:
        out(f"# 候选端口: {ports or '无'}")
    return [p for p in ports if _api_alive(p)]


# ── 认证 ────────────────────────────────────────────────────────────────
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_cookie(port: int) -> str:
    """用 ~/.dsh/.credentials.yaml 里的签名密钥，为这个端口现签一枚会话 cookie。

    与 DSH 内部的 browser-session 凭据同一套 scheme（v1.hmac-sha256），
    所以不需要读取进程内存里的启动令牌。

    这是本地回退路径：密钥只在本机读取、不发送到任何远端。
    更保守的做法是用官方启动令牌（--token），见 cookie_from_token()。
    """
    if not os.path.exists(CREDENTIALS):
        raise SystemExit(f"找不到凭据文件: {CREDENTIALS}")
    text = open(CREDENTIALS, encoding="utf-8").read()
    start = text.find("client-connection/browser-session")
    if start < 0:
        raise SystemExit("凭据文件里没有 client-connection/browser-session 记录")
    match = re.search(r"secret:\s*([A-Za-z0-9_\-]+)", text[start:start + 400])
    if not match:
        raise SystemExit("凭据记录里没有 secret")
    raw = match.group(1)
    secret = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    authority = f"127.0.0.1:{port}"
    name = "dsh-auth-" + _b64url(hashlib.sha256(authority.encode()).digest())
    now = int(time.time() * 1000)
    payload = {"version": 1, "authority": authority, "issuedAt": now, "expiresAt": now + 86_400_000 * 30}
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{name}=v1.{body}.{sig}"


def cookie_from_token(port: int, token: str) -> str:
    """用 DSH 官方启动令牌换会话 cookie（不读任何本地密钥）。

    官方浏览器认证流程：GET /?token=<launch token> 返回 303，并把签好的
    会话 cookie 写进 Set-Cookie。令牌取自 DSH 启动时打印或打开的 URL。
    """

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    url = f"http://127.0.0.1:{port}/?token={urllib.parse.quote(token, safe='')}"
    try:
        opener.open(urllib.request.Request(url), timeout=10)
    except urllib.error.HTTPError as err:
        set_cookie = err.headers.get("Set-Cookie") or err.headers.get("set-cookie")
        if err.code in (301, 302, 303, 307, 308) and set_cookie:
            return set_cookie.split(";", 1)[0]
        raise SystemExit(f"令牌换 cookie 失败 HTTP {err.code}（令牌可能已过期）") from None
    raise SystemExit("令牌换 cookie 失败：没有收到重定向与 Set-Cookie")


# ── RPC ─────────────────────────────────────────────────────────────────
class Dsh:
    def __init__(self, port: int | None = None, token: str | None = None):
        self.port = port or self._pick_port()
        self.authority = f"127.0.0.1:{self.port}"
        self.base = f"http://{self.authority}"
        token = token or os.environ.get("DSH_API_TOKEN")
        self.cookie = cookie_from_token(self.port, token) if token else build_cookie(self.port)

    @staticmethod
    def _pick_port() -> int:
        ports = discover_instances()
        if not ports:
            raise SystemExit("没有找到正在运行的 DSH 实例；先启动 DSH 桌面端，或用 --port 指定端口")
        if len(ports) > 1:
            out(f"# 发现多个实例端口 {ports}，使用 {ports[0]}；可用 --port 指定")
        return ports[0]

    def call(self, endpoint: str, args: dict | None = None, timeout: int = DEFAULT_TIMEOUT):
        payload = {
            "type": "client-request",
            "rpcId": f"r-{uuid.uuid4().hex[:10]}",
            "method": endpoint,
            "payload": {"args": args or {"_request": {}}},
        }
        req = urllib.request.Request(
            f"{self.base}/api/{endpoint}",
            data=json.dumps(payload).encode(),
            headers={"Cookie": self.cookie, "Content-Type": "application/json", "Host": self.authority},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as err:
            detail = err.read()[:300].decode("utf-8", "replace")
            raise SystemExit(f"{endpoint} 失败 HTTP {err.code}: {detail}") from None
        except urllib.error.URLError as err:
            raise SystemExit(f"连不上 {self.base}: {err}") from None

        result = body.get("result", body)
        if isinstance(result, dict) and result.get("ok") is False:
            raise SystemExit(f"{endpoint} 失败: {json.dumps(result.get('error'), ensure_ascii=False)}")
        return result.get("value", result) if isinstance(result, dict) else result

    # 会话
    def sessions(self) -> list[dict]:
        return self.call("session/list", {"_request": {}}).get("items", [])

    def create(self, cwd: str | None = None, workspace: str | None = None, preset: str | None = None) -> str:
        request: dict = {}
        if workspace:
            request["workspaceId"] = workspace
        else:
            target = os.path.abspath(cwd or os.getcwd())
            registered = workspace_for(target)
            if registered:
                # 传 workspaceId，DSH 才会把会话挂进这个工作区（attachSession）
                request["workspaceId"] = registered
            else:
                out(f"# 目录未登记为工作区，按 cwd 创建: {target}")
                request["cwd"] = target
        if preset:
            request["agentPreset"] = preset
        return self.call("session/create", {"request": request})["sessionId"]

    def prompt(self, session_id: str, text: str, mode: str = "queue") -> dict:
        return self.call("session/prompt", {"request": {
            "sessionId": session_id,
            "requestId": str(uuid.uuid4()),
            "mode": mode,
            "content": [{"type": "text", "text": text}],
            "clientTimeZone": "Asia/Shanghai",
        }})


def read_workspaces() -> tuple[list[dict], str | None]:
    """读本地工作区登记（这个 DSH 版本没有 workspace/list 远程方法）。"""
    path = os.path.join(HOME, "storages", "workspace.json")
    if not os.path.exists(path):
        return [], None
    data = json.load(open(path, encoding="utf-8"))
    table = ((data.get("tables") or {}).get("workspaces")) or {}
    rows = [{"id": wid, **value} for wid, value in table.items()]
    return rows, (data.get("global") or {}).get("defaultWorkspaceId")


def workspace_for(path: str) -> str | None:
    """按目录找已登记的工作区 id。

    注意：session/create 只传 cwd 时，会话的目录是对的，但**不会**挂进工作区，
    侧边栏里看不到。要让会话真正属于某个工作区，必须传 workspaceId。
    """
    rows, _ = read_workspaces()
    target = os.path.normcase(os.path.abspath(path))
    for ws in rows:
        ws_path = ws.get("path") or ""
        if ws_path and os.path.normcase(os.path.abspath(ws_path)) == target:
            return ws["id"]
    return None


# ── 会话记录 ────────────────────────────────────────────────────────────
def session_file(session_id: str) -> str | None:
    """按 sessionId 在所有工作区目录下找会话记录文件。"""
    if not os.path.isdir(SESSIONS_DIR):
        return None
    for workspace in os.listdir(SESSIONS_DIR):
        candidate = os.path.join(SESSIONS_DIR, workspace, session_id)
        if os.path.isdir(candidate):
            for name in ("session.v4.jsonl.zstd", "session.v4.jsonl", "session.v3.jsonl.zstd", "session.v2.jsonl.zstd"):
                path = os.path.join(candidate, name)
                if os.path.exists(path):
                    return path
    return None


def read_events(session_id: str) -> list[dict]:
    path = session_file(session_id)
    if not path:
        raise SystemExit(f"找不到会话记录: {session_id}")
    with open(path, "rb") as handle:
        raw = handle.read()
    text = None
    if path.endswith(".zstd"):
        try:
            import zstandard  # type: ignore
        except ImportError:
            raise SystemExit("读取压缩会话需要 zstandard：pip install zstandard") from None
        import io
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw)) as reader:
            text = reader.read().decode("utf-8", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def event_text(event: dict) -> str:
    """取一条消息的可读文本。

    两种结构都要支持：user/message 把内容放在 data.content，
    assistant/message 放在 data.message.content（内含 reasoning / tool-call / text）。
    """
    data = event.get("data") or {}
    content = data.get("content")
    if content is None and isinstance(data.get("message"), dict):
        content = data["message"].get("content")
    parts = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") in (None, "text") and isinstance(part.get("text"), str):
                parts.append(part["text"])
    elif isinstance(content, str):
        parts.append(content)
    return "".join(parts)


def memory_blocks(session_id: str) -> list[dict]:
    """这个会话被注入了哪些记忆（stable 长期底色 + recall 本轮召回）。"""
    blocks = []
    for event in read_events(session_id):
        source = (event.get("data") or {}).get("source") or {}
        if isinstance(source, dict) and source.get("kind") == "basic-memory":
            blocks.append({"form": source.get("form"), "seq": event.get("seq"), "text": event_text(event)})
    return blocks


def conversation(session_id: str) -> list[dict]:
    """人话版对话：用户说了什么、助手回了什么（跳过没有正文的中间步骤）。"""
    rows = []
    for event in read_events(session_id):
        kind = event.get("type")
        if kind not in ("user/message", "assistant/message"):
            continue
        data = event.get("data") or {}
        source = data.get("source") or {}
        tag = source.get("kind") if isinstance(source, dict) else None
        if kind == "user/message":
            # 只保留真人输入：工作区指令、技能清单、记忆注入等都不算对话
            if tag != "user":
                continue
        text = event_text(event).strip()
        if kind == "assistant/message" and not text:
            if data.get("interrupted"):
                rows.append({"role": "assistant", "seq": event.get("seq"), "text": "", "interrupted": True})
            continue
        rows.append({"role": "user" if kind == "user/message" else "assistant", "seq": event.get("seq"), "text": text})
    return rows


def wait_turn_text(session_id: str, timeout: int = 180) -> str:
    """发完消息后等这一轮结束，返回这一轮的助手正文。

    没等到正文时说明原因（中断 / 只调了工具），不静默返回空串。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            events = read_events(session_id)
        except SystemExit:
            time.sleep(1)
            continue
        if any(e.get("type") == "turn/end" for e in events):
            rows = [r for r in conversation(session_id) if r["role"] == "assistant"]
            if rows:
                last = rows[-1]
                if last.get("interrupted"):
                    raise SystemExit(f"会话 {session_id} 这一轮被中断，没有产出正文")
                if last["text"]:
                    return last["text"]
            raise SystemExit(f"会话 {session_id} 这一轮结束了，但没有助手正文（可能只执行了工具调用）")
        time.sleep(1.5)
    raise SystemExit(f"等待会话 {session_id} 完成超时（{timeout}s）")


# ── 命令 ────────────────────────────────────────────────────────────────
def cmd_instances(args) -> None:
    pids = _dsh_pids()
    ports = _listening_ports(pids)
    alive = [p for p in ports if _api_alive(p)]
    if args.json:
        emit_json({"pids": sorted(pids), "candidatePorts": ports, "apiPorts": alive})
        return
    out(f"DSH 进程 {sorted(pids) or '无'}")
    out(f"API 端口 {alive or '无'}")
    for port in alive:
        dsh = Dsh(port)
        try:
            items = dsh.sessions()
            out(f"  {port}: {len(items)} 个会话")
        except SystemExit as err:
            out(f"  {port}: 认证失败 {err}")


def cmd_sessions(args) -> None:
    dsh = Dsh(args.port, getattr(args, "token", None))
    items = dsh.sessions()
    rows = []
    for item in items:
        values = ((item.get("projections") or {}).get("values") or {})
        rows.append({
            "sessionId": item.get("sessionId"),
            "cwd": item.get("cwd"),
            "title": values.get("title"),
            "running": item.get("running"),
            "preset": values.get("agentPreset"),
            "updatedAt": item.get("updatedAt"),
        })
    if not args.all:
        rows = rows[: args.limit]
    if args.json:
        emit_json(rows)
        return
    for row in rows:
        title = row["title"] or "(未命名)"
        state = "运行中" if row["running"] else "空闲"
        out(f"{row['sessionId']}  {state:4}  {row['cwd']}  {title}")


def cmd_ask(args) -> None:
    dsh = Dsh(args.port, getattr(args, "token", None))
    cwd = os.path.abspath(args.cwd or os.getcwd())
    session_id = dsh.create(cwd=cwd, workspace=args.workspace, preset=args.preset)
    out(f"会话 {session_id}（工作区 {cwd}）")
    metadata = [s for s in dsh.sessions() if s.get("sessionId") == session_id]
    if metadata and metadata[0].get("cwd") != cwd and not args.workspace:
        out(f"注意：会话 cwd 是 {metadata[0].get('cwd')}，与请求的 {cwd} 不一致")
    dsh.prompt(session_id, args.text)
    if args.no_wait:
        out("已发送（未等待回复）")
        return
    out("等待回复…")
    reply = wait_turn_text(session_id, args.timeout)
    out("")
    out(reply.strip())


def cmd_new(args) -> None:
    dsh = Dsh(args.port, getattr(args, "token", None))
    cwd = os.path.abspath(args.cwd or os.getcwd())
    session_id = dsh.create(cwd=cwd, workspace=args.workspace, preset=args.preset)
    out(f"{session_id}（工作区 {cwd}）")


def cmd_send(args) -> None:
    dsh = Dsh(args.port, getattr(args, "token", None))
    dsh.prompt(args.session, args.text, mode=args.mode)
    out(f"已投递到 {args.session}")
    if args.wait:
        out(wait_turn_text(args.session, args.timeout).strip())


def cmd_history(args) -> None:
    rows = conversation(args.session)
    if args.json:
        emit_json(rows)
        return
    for row in rows:
        who = "我" if row["role"] == "user" else "DSH"
        text = row["text"].strip()
        if not args.full and len(text) > args.chars:
            text = text[: args.chars] + "…"
        out(f"[{who}] {text}")
        out("")


def cmd_memory(args) -> None:
    blocks = memory_blocks(args.session)
    if args.json:
        emit_json(blocks)
        return
    if not blocks:
        out("这个会话没有注入记忆")
        return
    for block in blocks:
        label = "长期底色(stable)" if block["form"] == "stable" else f"本轮召回(recall)"
        out(f"── {label} seq={block['seq']} {len(block['text'])} 字 ──")
        text = block["text"]
        if not args.full and len(text) > args.chars * 4:
            text = text[: args.chars * 4] + "…"
        out(text.strip())
        out("")


def cmd_workspaces(args) -> None:
    """工作区登记在 ~/.dsh/storages/workspace.json（v2: tables.workspaces 映射），直接读文件。"""
    path = os.path.join(HOME, "storages", "workspace.json")
    if not os.path.exists(path):
        raise SystemExit(f"找不到工作区登记: {path}")
    data = json.load(open(path, encoding="utf-8"))
    table = ((data.get("tables") or {}).get("workspaces")) or {}
    default_id = (data.get("global") or {}).get("defaultWorkspaceId")
    rows = [{"id": wid, **value} for wid, value in table.items()]
    if args.json:
        emit_json({"defaultWorkspaceId": default_id, "workspaces": rows})
        return
    here = os.path.normcase(os.path.abspath(os.getcwd()))
    for ws in rows:
        ws_path = ws.get("path") or ""
        marks = []
        if os.path.normcase(os.path.abspath(ws_path)) == here:
            marks.append("← 当前目录")
        if ws["id"] == default_id:
            marks.append("默认")
        suffix = ("  " + " ".join(marks)) if marks else ""
        out(f"{ws['id']}  {ws_path}  会话 {len(ws.get('sessionIds') or [])}{suffix}")


def add_common(parser: argparse.ArgumentParser) -> None:
    """让 --port / --json / --token 既能写在子命令前，也能写在子命令后。"""
    parser.add_argument("--port", type=int, default=argparse.SUPPRESS, help="DSH API 端口；默认自动发现")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="输出 JSON")
    parser.add_argument("--token", default=argparse.SUPPRESS, help="DSH 启动令牌（官方认证方式，优先于本地密钥）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dshctl", description="操作正在运行的 DSH 实例：会话、消息、记录、记忆")
    parser.add_argument("--port", type=int, default=None, help="DSH API 端口；默认自动发现")
    parser.add_argument("--json", action="store_true", default=False, help="输出 JSON，便于脚本消费")
    parser.add_argument("--token", default=None, help="DSH 启动令牌（也可用环境变量 DSH_API_TOKEN）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("instances", help="列出正在运行的 DSH 实例")
    add_common(p)
    p.set_defaults(func=cmd_instances)

    p = sub.add_parser("sessions", help="列出会话")
    add_common(p)
    p.add_argument("--all", action="store_true")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("workspaces", help="列出工作区")
    add_common(p)
    p.set_defaults(func=cmd_workspaces)

    p = sub.add_parser("new", help="新建会话（默认当前目录）")
    add_common(p)
    p.add_argument("--cwd")
    p.add_argument("--workspace")
    p.add_argument("--preset")
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("ask", help="新建会话并发送一条消息，等回复")
    add_common(p)
    p.add_argument("text")
    p.add_argument("--cwd")
    p.add_argument("--workspace")
    p.add_argument("--preset")
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--no-wait", action="store_true")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("send", help="向已有会话发消息")
    add_common(p)
    p.add_argument("session")
    p.add_argument("text")
    p.add_argument("--mode", choices=["queue", "steer"], default="queue")
    p.add_argument("--wait", action="store_true")
    p.add_argument("--timeout", type=int, default=180)
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("history", help="读会话对话")
    add_common(p)
    p.add_argument("session")
    p.add_argument("--chars", type=int, default=400)
    p.add_argument("--full", action="store_true")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("memory", help="看会话注入了哪些记忆")
    add_common(p)
    p.add_argument("session")
    p.add_argument("--chars", type=int, default=200)
    p.add_argument("--full", action="store_true")
    p.set_defaults(func=cmd_memory)

    return parser


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

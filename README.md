# dshctl

Control a **running** DeepSeek Harness (DSH) instance from scripts: create sessions in the
right workspace, send prompts, wait for replies, and read back the conversation and the
memory blocks that were injected into it.

No clicking. No restart. No separate agent runtime.

```console
$ dshctl instances
DSH 进程 [13928, 20532, ...]
API 端口 [49890]
  49890: 133 个会话

$ dshctl ask "summarize today's logs"
会话 session-3e270bb9-...（工作区 E:\VScode\ai）
等待回复…
```

## Why this exists

DSH already ships a `headless` profile: one task, one answer, process exits. That is great
for batch jobs, but it does not let you reach the instance you are actually using — the
desktop app with your workspace, skills, plugins, and memory already loaded.

`dshctl` talks to that live instance's own `/api` Remote gateway, so anything you script
shows up in the same GUI, in the same workspace, with the same plugins.

## Install

Python 3.10+, standard library only (one optional dependency for reading compressed
session logs):

```console
git clone https://github.com/<you>/dshctl
cd dshctl
python -m pip install zstandard   # optional: needed for `history` / `memory`
```

Put the folder on `PATH` (Windows: `dshctl.cmd` is included) or call `python dshctl.py`.

## Commands

| Command | What it does |
|---|---|
| `dshctl instances` | Find running DSH processes and their API ports |
| `dshctl workspaces` | List registered workspaces, marking the current directory |
| `dshctl sessions [--limit N] [--all]` | List sessions with state, cwd, title |
| `dshctl new [--cwd DIR] [--workspace ID] [--preset NAME]` | Create a session |
| `dshctl ask "TEXT" [--timeout S]` | Create a session in the current workspace, send a prompt, print the reply |
| `dshctl send SESSION "TEXT" [--wait] [--mode queue\|steer]` | Send to an existing session |
| `dshctl history SESSION [--chars N] [--full]` | Read the user/assistant conversation |
| `dshctl memory SESSION [--json]` | Show the memory blocks injected into that session |

`--port`, `--json`, and `--token` work before or after the subcommand.

## How it works

**Port discovery.** DSH binds a fresh HTTP port on every launch (we observed 63195 → 49890).
`dshctl` never hardcodes it: it lists listening ports owned by the `DeepSeek Harness`
process, then confirms the API port by the fact that an unauthenticated request returns
`401`.

**Authentication.** Two paths:

1. **Official launch token** — pass `--token` (or set `DSH_API_TOKEN`) with the token from the
   URL DSH prints/opens at startup. `dshctl` does `GET /?token=…`, receives the signed
   session cookie from `Set-Cookie`, and uses it. No local secret is read.
2. **Local fallback** — if no token is given, `dshctl` reads the `client-connection/browser-session`
   signing secret from `~/.dsh/.credentials.yaml` and mints an equivalent cookie with the
   same `v1.HMAC-SHA256` scheme DSH itself uses. The secret is read locally and never
   transmitted anywhere.

**Wire format.** Requests are `POST /api/<method>` with a client-request envelope:

```json
{"type":"client-request","rpcId":"…","method":"session/create",
 "payload":{"args":{"request":{"workspaceId":"…"}}}}
```

**Workspace attachment — the trap.** `session/create` accepts either `cwd` or `workspaceId`.
Passing only `cwd` gives the session the right directory but does **not** attach it to the
workspace, so it never shows up in the sidebar. DSH only calls `attachSession` when the
request carries a `workspaceId`. `dshctl` resolves the current directory to a registered
workspace first, and only falls back to `cwd` (with a warning) for unregistered directories.

**Reading logs.** Session records live at
`~/.dsh/sessions/<workspace>/<sessionId>/session.v4.jsonl.zstd` — zstd-compressed JSONL.
Assistant text lives under `data.message.content`; user text under `data.content`. Anything
that is not a plain `text` part (reasoning, tool calls) is skipped.

## Use case: verifying what memory a keyword recalls

```console
$ dshctl ask "定时任务" --no-wait
$ dshctl memory <sessionId>
── 长期底色(stable) seq=11 2479 字 ──
── 本轮召回(recall) seq=13 1021 字 ──
### 定时任务（相关度 1.22）
…
```

`ask` with `--no-wait` returns immediately; `memory` then shows exactly which notes were
injected for that prompt. Useful when you are tuning retrieval thresholds, or when you want
proof that a plugin actually injected something (the log line says "injected", the session
record shows *what*).

## Prior art / similar tools

DSH is open source (MIT) with a large ecosystem. Related projects worth knowing:

- [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) — the harness itself; official `headless` profile, `sdk-minimal` profile and SDK packages
- [ccch1mneyyy/dsh-Go](https://github.com/ccch1mneyyy/dsh-Go) — run DSH on a phone and remote-control your computer
- [tommy0103/obelisk](https://github.com/tommy0103/obelisk) — make past sessions/subagents queryable
- [YouHui1/dsh-sessions-diagnosis](https://github.com/YouHui1/dsh-sessions-diagnosis) — diagnose sessions that stopped opening
- [yamingmou/dsh-log-contract](https://github.com/yamingmou/dsh-log-contract) — session log contract checks
- [Larrtroffen/harnessbridge](https://github.com/Larrtroffen/harnessbridge) — session migration/bridge

`dshctl` is deliberately narrow: a small CLI that drives the *already running* instance and
reads back what it recorded. If you need a runtime of your own, use the official `headless`
or `sdk-minimal` profiles instead.

## Limits

- Requires a running DSH desktop/web instance. Headless runs have no HTTP gateway to attach to.
- Port discovery uses `tasklist`/`netstat`, so it is Windows-first. Elsewhere, pass `--port`.
- `history` / `memory` need `zstandard`.
- Internal APIs. Method names and the log format are version-specific (`session.v4`), and an
  upgrade may change them. Treat this as a userland tool, not a stable SDK.
- Reads your own local machine and your own credentials. Do not point it at machines you do
  not own.

## License

MIT

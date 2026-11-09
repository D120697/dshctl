# Security notes

`dshctl` runs on your machine, talks to `127.0.0.1` only, and sends nothing to any remote
service. It contains no telemetry.

## What it can read

| Path | Why | When |
|---|---|---|
| `~/.dsh/.credentials.yaml` | `client-connection/browser-session` signing secret, used to mint a local session cookie | only when no `--token` is given |
| `~/.dsh/sessions/**/session.v4.jsonl.zstd` | your own session transcripts | `history` / `memory` |
| `~/.dsh/storages/workspace.json` | workspace id ↔ directory mapping | `workspaces`, session creation |

Nothing is copied, uploaded, logged to disk, or printed. The secret is used in memory to
compute an HMAC and is never included in output.

## Preferred authentication

Use the official launch token instead of the local secret:

```console
dshctl --token <launch token from the DSH URL> sessions
```

This performs the same `GET /?token=…` exchange the browser does, and avoids touching the
credentials file at all. Prefer this on shared or audited machines.

## Scope

Everything here is local, single-user, and assumes you own both the machine and the DSH
installation. There is no multi-user model, no remote exposure, and no way to authenticate
to an instance belonging to someone else.

## Reporting

Open an issue for anything that looks like it could leak a secret or reach a non-local host.

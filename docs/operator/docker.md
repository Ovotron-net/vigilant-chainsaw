# Docker on Windows (Docker Desktop only)

This compose stack targets **Windows + Docker Desktop** (Linux containers).
It does **not** use host networking or `CAP_NET_RAW`.

| Capability | On Docker Desktop |
|---|---|
| Probe / ops HTTP | Yes — published ports `9108` / `9109` |
| Embedded dashboard | Yes — `http://127.0.0.1:9109/` |
| Policy validate | Yes — `tools` profile |
| Classic PCAP replay | Yes — `replay` profile |
| Live AF_PACKET capture | **No** — process stays degraded (`capture_point_unavailable`) |

Production live capture remains a **native Linux** deploy (systemd), not this
Desktop stack. See [runbook.md](runbook.md).

## Prerequisites

- Docker Desktop for Windows with **Linux containers** enabled
- PowerShell (or Windows Terminal)
- Ports **9108** and **9109** free on the host

## Quick start

```powershell
cd <repo>
Copy-Item .env.example .env -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path data\logs, data\lib | Out-Null

docker compose up --build -d
docker compose ps
docker compose logs -f monitor
```

From the Windows host:

```powershell
curl.exe -sS http://127.0.0.1:9108/healthz
curl.exe -sS http://127.0.0.1:9108/readyz
curl.exe -sS http://127.0.0.1:9108/metrics
curl.exe -sS http://127.0.0.1:9109/api/state
# browser: http://127.0.0.1:9109/
```

Expect `/readyz` **503** with `capture_point_unavailable` — that is normal on
Desktop. `/healthz` should still be **200** while the process is up.

Stop:

```powershell
docker compose down
```

## Layout

| Host (Windows) | Container | Notes |
|---|---|---|
| `config/policy.v2.docker.json` | `/etc/ibn-monitor/policy.v2.json` | RO bind (`$IBN_POLICY` override) |
| `.\data\logs` | `/var/log/ibn-monitor` | journal JSONL |
| `.\data\lib` | `/var/lib/ibn-monitor` | reserved state |
| `localhost:9108` | probe | published |
| `localhost:9109` | ops + dashboard | published |

Image defaults: non-root uid **950**, `tini`, read-only rootfs, `/tmp` tmpfs.

## Policy (Desktop)

[`config/policy.v2.docker.json`](../../config/policy.v2.docker.json):

- journal → `/var/log/ibn-monitor/events-v2.jsonl`
- probe/ops bind **`0.0.0.0`** so published ports work
- ops `allow_non_loopback: true` (required for non-loopback bind; Desktop-only trust model — do not expose these ports on untrusted networks)
- `notifications.webhook_url_env: IBN_WEBHOOK_URL`

Webhook (optional):

```powershell
# .env
IBN_WEBHOOK_URL=https://your-authorized-endpoint.example/events
docker compose up -d
```

## Offline profiles

Validate:

```powershell
docker compose --profile tools run --rm validate
```

Replay (needs a classic PCAP on the host):

```powershell
python scripts/generate_test_pcap.py
docker compose --profile replay run --rm replay
# output: .\data\logs\replay-v2.jsonl
```

## Security notes (Desktop)

- Ports are published on the Windows host loopback mapping; treat **9109** as
  sensitive (no auth on the sensor). Prefer firewall / not binding to LAN.
- `allow_non_loopback` is for container bridge networking, not for public
  exposure.
- No `NET_ADMIN` / no `NET_RAW` in this stack.

## Troubleshooting

| Symptom | Check |
|---|---|
| Port already in use | `netstat -ano \| findstr :9108` — free the port or change compose `ports` |
| Connection refused | `docker compose ps` — container up? `docker compose logs monitor` |
| `/readyz` 503 | Expected on Desktop (no live capture) |
| Journal permission errors | Ensure `data\logs` exists; recreate container |
| Wrong engine | Docker Desktop → Settings → General → Use Linux containers |

Snapshot contract: [ops-state-api.md](ops-state-api.md).

# ibn-monitor — Intent-Based Continuous Traffic Monitor

A deployable Linux network sensor that evaluates captured IP traffic against declarative intent policies. It logs violations as JSON Lines, sends optional webhook notifications, exposes health and Prometheus-compatible metrics, and can render `action=drop` policies into an `nftables` forwarding ruleset.

> Use this software only on networks and systems you own or are explicitly authorized to monitor.

## What it does

- Captures IPv4 and IPv6 packet metadata continuously via Scapy.
- Evaluates source CIDRs, destination CIDRs, protocol, and destination ports against named rules.
- Does **not** store packet payloads — only IP/transport header fields.
- Writes rotating structured event logs (JSONL).
- Sends optional webhook notifications off the capture thread with per-rule deduplication.
- Exposes `/healthz`, `/readyz`, and `/metrics` (Prometheus text format), plus a built-in web dashboard at `/` (backed by `/api/state`) showing live metrics, loaded rules, and recent violations.
- Reloads policy rules on `SIGHUP` without interrupting packet capture.
- Processes PCAP files offline for testing and incident review.
- Generates an `nftables` ruleset from the same policy file for gateway enforcement.

## Architecture

```text
Network interface / PCAP
          │
          ▼
    Scapy capture  (AsyncSniffer or offline PCAP)
          │
          ▼
  packet_to_metadata()          ← capture.py
          │
          ▼
  PolicyEngine.evaluate()       ← engine.py  (RLock, live SIGHUP reload)
          │
     matched rules
          │
          ├──▶ EventLog (JSONL + recent) ← events.py
          ├──▶ Notifier (webhook worker) ← events.py  (queue.Queue, dedup)
          └──▶ Prometheus metrics        ← events.py / health.py

config/policy.json ──▶ nftables renderer ──▶ gateway enforcement
                                              (render-nftables, separate step)
```

Ten focused modules under `src/ibn_monitor/` — no framework, no ORM:

| Module | Role |
|---|---|
| `models.py` | Frozen dataclasses: `PacketMetadata`, `Rule` |
| `config.py` | Loads and validates `policy.json` → `AppConfig`; raises `ConfigError` on bad data |
| `capture.py` | `PacketSource` seam, live and PCAP Scapy adapters, packet metadata extraction |
| `engine.py` | `PolicyEngine` — CIDR matching, thread-safe rule swap via `RLock` |
| `events.py` | `Metrics`, `EventLog` (JSONL + recent ring), `Notifier` seam (`NullNotifier` / `WebhookNotifier`) |
| `health.py` | HTTP server for `/healthz`, `/readyz`, `/metrics`, `/api/state`, and the `/` dashboard |
| `dashboard.py` | Embedded single-page dashboard (design-token CSS, no build step) |
| `enforcement.py` | Renders `action=drop` rules into an `inet ibn_monitor` nftables table |
| `monitor.py` | `MonitorService` — wires everything together |
| `cli.py` | Four subcommands: `validate`, `check`, `render-nftables`, `run` |

## Requirements

- **OS**: Linux required for live capture and nftables enforcement. Windows/macOS support development, testing, and PCAP replay only.
- **Python**: 3.11 or newer.
- **System packages (Linux)**: `libpcap0.8` (BPF capture filters), `nftables` (enforcement only).
- **Capabilities (Linux)**: `CAP_NET_RAW` (or root) for packet capture; `CAP_NET_ADMIN` only when applying firewall rules.

## Installation

**Development (Windows / PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"          # includes pytest, pytest-cov, ruff

ibn-monitor validate --config config/policy.json
```

**Production (Linux)**

```bash
sudo apt-get update
sudo apt-get install -y python3-venv libpcap0.8 nftables

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ibn-monitor validate --config config/policy.json
```

Identify the correct capture interface on Linux, then update `sensor.interface` in `config/policy.json`:

```bash
ip -brief link
```

Start live monitoring (Linux, requires `CAP_NET_RAW`):

```bash
sudo .venv/bin/ibn-monitor run --config config/policy.json
```

Events are written to `/var/log/ibn-monitor/events.jsonl` by the example configuration.

## Policy model

Rules are defined in `config/policy.json` and validated against the packaged schema `ibn_monitor/policy.schema.json` at startup.

```json
{
  "version": 1,
  "sensor": { "interface": "eth0", "bpf_filter": "ip or ip6", "promiscuous": false },
  "logging": { "file": "/var/log/ibn-monitor/events.jsonl", "max_bytes": 10485760, "backup_count": 5 },
  "health":  { "enabled": true, "bind": "127.0.0.1", "port": 9108 },
  "notifications": {
    "webhook_url_env": "IBN_WEBHOOK_URL",
    "timeout_seconds": 3,
    "minimum_severity": "high",
    "deduplication_seconds": 60
  },
  "rules": [
    {
      "id": "DEV-TO-PROD-DB",
      "description": "Development systems must not connect directly to PostgreSQL in production",
      "enabled": true,
      "source_cidrs": ["10.20.0.0/16"],
      "destination_cidrs": ["10.50.10.8/32"],
      "protocol": "tcp",
      "destination_ports": [5432],
      "severity": "critical",
      "action": "drop"
    }
  ]
}
```

**Action semantics**:

- `alert` — detect and log only.
- `drop` — detect, log, and eligible for nftables rendering. The sensor itself never drops packets; enforcement is a separate step.

**Validation constraints** (schema + `config.py`):

- Rule IDs must be unique (`config.py`).
- `destination_ports` must be empty or absent when `protocol` is `icmp` (JSON Schema `if`/`then`).
- `notifications.webhook_url_env` is an **environment variable name**, never the URL itself.
- `SIGHUP` reloads rules only. Changes to `sensor`, `logging`, or `health` require a restart.

## Testing flows

**Syntax-check a specific flow without capturing packets** (exit code `2` = match found):

```powershell
ibn-monitor check `
  --config config/policy.json `
  --source 10.20.5.14 `
  --destination 10.50.10.8 `
  --protocol tcp `
  --destination-port 5432
```

**Replay a PCAP file** (no root required):

```powershell
python scripts\generate_test_pcap.py
ibn-monitor run --config config/policy.json --pcap test-traffic.pcap
```

**Run the test suite**:

```powershell
make test     # pytest with coverage
make lint     # ruff check .
```

Or without `make`:

```powershell
pytest                  # runs with coverage per pyproject.toml settings
ruff check .
```

## Webhook notifications

Set the environment variable named in `notifications.webhook_url_env`:

```powershell
$env:IBN_WEBHOOK_URL = 'https://your-authorized-endpoint.example/events'
ibn-monitor run --config config/policy.json
```

On Linux, preserve the variable when escalating with `sudo`:

```bash
export IBN_WEBHOOK_URL='https://your-authorized-endpoint.example/events'
sudo --preserve-env=IBN_WEBHOOK_URL .venv/bin/ibn-monitor run --config config/policy.json
```

The receiver gets the same JSON object written to the local log. Webhook URLs are secrets — never commit them. Notifications with the same rule ID, source, destination, protocol, and destination port are deduplicated for `deduplication_seconds`, but every event is still recorded locally.

## Health and metrics

The health listener binds to `127.0.0.1:9108` by default:

```powershell
curl.exe http://127.0.0.1:9108/healthz    # {"status":"ok"}
curl.exe http://127.0.0.1:9108/readyz     # {"ready":true} once sniffing
curl.exe http://127.0.0.1:9108/metrics    # Prometheus text format
curl.exe http://127.0.0.1:9108/api/state  # metrics + rules + recent violations as JSON
```

Opening `http://127.0.0.1:9108/` in a browser serves a built-in dashboard showing the underlying monitor state: live metrics, the loaded policy rules, and the most recent violations (auto-refreshing every 3 seconds).

> Use `curl.exe` in PowerShell to invoke the real curl binary. The built-in `curl` alias maps to `Invoke-WebRequest`, which has different output formatting.

Do not expose the health endpoint to untrusted networks without additional access controls.

## Docker

Live capture requires host networking and Linux capabilities:

```powershell
New-Item -ItemType Directory -Force data\logs
docker compose up --build -d
docker compose logs -f
```

The Compose file mounts `config/policy.json` read-only and writes logs to `./data/logs`. Set `$env:IBN_WEBHOOK_URL` in your shell and it will be forwarded automatically.

## systemd (Linux only)

```bash
sudo ./scripts/install-systemd.sh
sudo systemctl status ibn-monitor
sudo journalctl -u ibn-monitor -f
```

Reload rules after editing `/etc/ibn-monitor/policy.json`:

```bash
sudo systemctl reload ibn-monitor   # sends SIGHUP
```

Changes to the capture interface, BPF filter, log path, or health listener require a full restart.

## nftables enforcement (Linux only)

Generate and validate the firewall ruleset before applying it:

```bash
ibn-monitor render-nftables \
  --config config/policy.json \
  --output build/ibn-monitor.nft

sudo nft --check --file build/ibn-monitor.nft   # dry-run validation
sudo nft --file build/ibn-monitor.nft            # apply
sudo nft list table inet ibn_monitor
```

Rendering the ruleset works on Windows/PowerShell; applying it requires Linux and `nft`:

```powershell
ibn-monitor render-nftables `
  --config config/policy.json `
  --output build/ibn-monitor.nft
```

Or use the helper script (Linux):

```bash
sudo ./scripts/apply-nftables.sh config/policy.json
```

**Deployment notes**:

- The generated chain hooks at `forward`. Deploy on the gateway or firewall carrying the traffic.
- The rules replace only the `inet ibn_monitor` table, leaving the rest of the host firewall intact.
- Validate in a non-production environment first.
- Ensure out-of-band or console access before changing a remote firewall.
- Persistent loading is distribution-specific; integrate the generated file with your platform's nftables service.

## Event format

Every violation is written as a single JSON object on one line:

```json
{
  "schema_version": 1,
  "event_id": "9a790d64-b9d4-47e1-89bc-b469b72a3063",
  "event_type": "network_policy_violation",
  "observed_at": "2026-07-17T18:21:44.842911+00:00",
  "rule": {
    "id": "DEV-TO-PROD-DB",
    "description": "Development systems must not connect directly to PostgreSQL in production",
    "severity": "critical",
    "action": "drop"
  },
  "network": {
    "timestamp": "2026-07-17T18:21:44.842911+00:00",
    "interface": "eth0",
    "source": "10.20.5.14",
    "destination": "10.50.10.8",
    "protocol": "tcp",
    "source_port": 50000,
    "destination_port": 5432,
    "packet_length": 40,
    "tcp_flags": "S"
  }
}
```

## CI / GitHub Actions

GitHub Actions runs Ruff, the test suite across all supported Python versions, and a Docker build on every push. The monitor itself must run on an authorized Linux sensor or gateway — not a standard GitHub-hosted Actions runner.

To publish:

```powershell
git init
git add .
git commit -m "Add intent-based continuous traffic monitor"
git branch -M main
git remote add origin git@github.com:YOUR-USERNAME/ibn-continuous-traffic-monitor.git
git push -u origin main
```

## Security considerations

- The monitor captures IP/transport header metadata only — never application payloads.
- A host sensor sees only traffic delivered to or observable by that host. Use a TAP, SPAN/mirror port, or cloud-native traffic-mirroring for broader visibility.
- Encrypted traffic exposes network-layer metadata but not protected application content.
- Detection is not enforcement. Apply generated firewall rules only after controlled validation.
- Treat the policy file, log directory, health endpoint, and webhook receiver as access-controlled resources.

## License

GPL-2.0-only — see [LICENSE](LICENSE).

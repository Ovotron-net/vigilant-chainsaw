# AGENTS.md — ibn-monitor

Intent-Based Continuous Traffic Monitor: a Linux network sensor that captures IP metadata via Scapy, evaluates it against declarative JSON policies, logs violations as JSONL, and renders `action=drop` rules into nftables.

## Architecture

Ten focused modules under `src/ibn_monitor/`; no framework, no ORM:

| Module | Role |
|---|---|
| `models.py` | Frozen dataclasses: `PacketMetadata`, `Rule`. All immutable (`frozen=True, slots=True`). |
| `config.py` | Loads and validates `policy.json` → `AppConfig`. Raises `ConfigError` on bad data. |
| `capture.py` | `PacketSource` seam (`typing.Protocol`) plus the two Scapy adapters: `ScapyLiveSource` (AsyncSniffer) and `PcapReplaySource` (offline replay). Owns `packet_to_metadata()` and all Scapy imports. |
| `engine.py` | `PolicyEngine` — evaluates packets against rules using `ipaddress` CIDR matching. Thread-safe via `RLock` (supports live SIGHUP reload). Pure policy; no Scapy. |
| `events.py` | `Metrics`, `EventLog` (JSONL + recent ring), `Notifier` seam (`NullNotifier` / `WebhookNotifier`). |
| `health.py` | Minimal HTTP server exposing `/healthz`, `/readyz`, `/metrics` (Prometheus text format), `/api/state` (metrics + rules + recent events JSON), and `/` (embedded HTML dashboard). |
| `dashboard.py` | Static single-page dashboard served at `/`. Semantic OKLCH design-token CSS embedded as a Python string; polls `/api/state` every 3 s. No build step, no external assets. |
| `enforcement.py` | Renders `action=drop` rules into an `inet ibn_monitor` nftables table. |
| `monitor.py` | `MonitorService` — wires engine, EventLog, Notifier, and health around an injected `PacketSource`. |
| `cli.py` | Four subcommands: `validate`, `check`, `render-nftables`, `run`. Composition root: picks the `PacketSource` adapter for `run`. |

**Data flow**: `PacketSource` adapter (capture) → `packet_to_metadata()` → callback with `PacketMetadata | None` → `PolicyEngine.evaluate()` → matched `Rule` list → `create_event()` → `EventLog.write()` + `Notifier.notify()` → JSONL + optional webhook + metrics.

**PacketSource contract**: `start(callback)` returns when capture is established (live) or the source is exhausted (finite: PCAP replay, in-memory test sources). `stop()` is idempotent. Tests inject an in-memory source — no Scapy mocking needed for `MonitorService` tests.

## Essential Commands

```bash
# Install for development
pip install -e ".[dev]"       # installs pytest, pytest-cov, ruff

# Run tests with coverage
make test                     # pytest tests/ --cov

# Lint
make lint                     # ruff check .

# Validate policy.json against schema
make validate                 # ibn-monitor validate --config config/policy.json

# Test a specific flow without capturing packets (exit code 2 = match found)
make check
ibn-monitor check --config config/policy.json \
  --source 10.20.5.14 --destination 10.50.10.8 --protocol tcp --destination-port 5432

# Replay a PCAP file (no root needed)
ibn-monitor run --config config/policy.json --pcap test-traffic.pcap

# Render nftables rules (does not apply them)
ibn-monitor render-nftables --config config/policy.json --output build/ibn-monitor.nft

# Docker (requires Linux for live capture)
make docker                   # docker compose up --build -d
```

## Configuration

`config/policy.json` is validated against `config/policy.schema.json` at startup. Key constraints enforced in `config.py`:

- Rule IDs must be unique across the file.
- `destination_ports` must be empty/absent when `protocol` is `icmp`.
- `notifications.webhook_url_env` names an **environment variable** that holds the URL (never the URL itself).
- SIGHUP reloads rules only; changes to `sensor`, `logging`, or `health` require a restart.

## Testing Patterns

Tests live in `tests/`; conftest disables Scapy route auto-loading:

```python
# conftest.py — prevents Scapy from reading host routing table in CI
from scapy.config import conf

conf.route_autoload = False
conf.route6_autoload = False
```

Use the `rule()` factory helper (defined in test files) to build `Rule` instances with overridable defaults rather than constructing them inline:

```python
def rule(**kwargs):
    defaults = dict(id="R1", description="test", enabled=True, ...)
    return Rule(**{**defaults, **kwargs})
```

Temporary config files use pytest's `tmp_path` fixture; no mocking of Scapy is needed for engine/config unit tests.

## Key Conventions

- **Frozen models everywhere**: `PacketMetadata` and `Rule` are `@dataclass(frozen=True, slots=True)`. Do not add mutable state to models.
- **Thread boundaries**: Only `WebhookNotifier` crosses thread boundaries; webhook POSTs go onto a `queue.Queue` consumed by a daemon thread. `PolicyEngine` uses `RLock` for atomic rule swap on reload.
- **`ConfigError` for validation failures**: Raise `ConfigError` (not `ValueError`) for any policy/config problem caught in `config.py`.
- **Metrics naming**: Prometheus counters follow `ibn_monitor_<noun>_total`; gauges use `ibn_monitor_<noun>` (see `events.py`).
- **No payload capture**: The sensor only extracts IP/transport header fields; never buffer or log packet payload bytes.
- **`action` semantics**: `alert` = detect and log only. `drop` = detect, log, AND eligible for nftables rendering. The sensor itself never drops packets; enforcement is a separate `render-nftables` step.

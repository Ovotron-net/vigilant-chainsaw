# AGENTS.md — ibn-monitor

Intent-Based Continuous Traffic Monitor: a Linux network sensor that captures IP metadata via Scapy, evaluates it against declarative JSON policies, logs violations as JSONL, and renders `action=drop` rules into nftables.

Phase 1 also ships an additive **v2 core/replay** path: explicit v2 policy, compiled matching, bounded header decoding, classic-PCAP event-time replay, and schema-v2 evidence envelopes. Live `run` and `render-nftables` remain v1 until later phases.

## Architecture

Focused modules under `src/ibn_monitor/`; no framework, no ORM:

| Module | Role |
|---|---|
| `models.py` | Frozen dataclasses: v1 `PacketMetadata`/`Rule`/`Event` plus v2 `Observation`/`PolicyRule`/`EpisodeTransition`/`EvidenceEnvelope`. All immutable (`frozen=True, slots=True`). |
| `config.py` | V1 `load_config()` → `AppConfig`. V2 `validate_v2_config()` / `load_v2_config()` → `PolicyV2Config` with diagnostics and canonical revisions. Raises `ConfigError` on bad data. |
| `capture.py` | `PacketSource` seam (`typing.Protocol`) plus the two Scapy adapters: `ScapyLiveSource` (AsyncSniffer) and `PcapReplaySource` (offline replay). Owns `packet_to_metadata()` and all Scapy imports. |
| `engine.py` | V1 `PolicyEngine` — evaluates packets against rules using `ipaddress` CIDR matching. Thread-safe via `RLock` (supports live SIGHUP reload). Pure policy; no Scapy. |
| `policy.py` | V2 compiled-policy IR, all-match evaluation, and overlap diagnostics. No Scapy. |
| `decode.py` | Bounded Ethernet/SLL/raw IPv4/IPv6 header decoder → `Observation`. Header prefixes only; no payload. |
| `pcap.py` | Streaming classic-PCAP reader (header-only). Rejects PCAPNG. |
| `episodes.py` | Deterministic bounded violation-episode state machine. |
| `migration.py` | Pure v1 raw-JSON → v2 raw-JSON migration with ambiguity diagnostics. |
| `replay.py` | Event-time PCAP replay: watermark order, matching, episodes, evidence JSONL, summary. |
| `events.py` | V1 `Metrics`, `EventLog`, `Notifier`; v2 `EvidenceSequencer` / `serialize_evidence`. |
| `health.py` | Minimal HTTP server exposing `/healthz`, `/readyz`, `/metrics` (Prometheus text format), `/api/state` (metrics + rules + recent events JSON), and `/` (embedded HTML dashboard). |
| `dashboard.py` | Static single-page dashboard served at `/`. Semantic OKLCH design-token CSS embedded as a Python string; polls `/api/state` every 3 s. No build step, no external assets. |
| `enforcement.py` | Renders v1 `action=drop` rules into an `inet ibn_monitor` nftables table. |
| `monitor.py` | `MonitorService` — wires engine, EventLog, Notifier, and health around an injected `PacketSource`. |
| `cli.py` | Subcommands: `validate`, `check`, `migrate-policy`, `replay`, `render-nftables`, `run`. V2 validate/check/replay; live/render stay v1. |

**V1 data flow**: `PacketSource` adapter (capture) → `packet_to_metadata()` → callback with `PacketMetadata | None` → `PolicyEngine.evaluate()` → matched `Rule` list → `create_event()` → `EventLog.write()` + `Notifier.notify()` → JSONL + optional webhook + metrics.

**V2 replay flow**: classic PCAP → bounded decoder → `Observation` → `evaluate_policy` (all matches) → `EpisodeTracker` → `EvidenceSequencer` → schema-v2 JSONL + summary.

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
make validate-v2              # ibn-monitor validate --config config/policy.v2.example.json --strict

# Test a specific flow without capturing packets
# V1 exit code 2 = match found; V2 exit code 1 = match found, 2 = error
make check
ibn-monitor check --config config/policy.json \
  --source 10.20.5.14 --destination 10.50.10.8 --protocol tcp --destination-port 5432

# V1 offline PCAP via Scapy path (no root needed)
ibn-monitor run --config config/policy.json --pcap test-traffic.pcap

# V2 classic-PCAP event-time replay (no Scapy, no root)
python scripts/generate_test_pcap.py
make replay-v2
# or:
ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap \
  --output build/replay-v2.jsonl --summary-output -

# Migrate unambiguous v1 policy → v2 candidate
ibn-monitor migrate-policy --config config/policy.json --output build/policy.v2.json \
  --sensor-id edge-gw-01 --topology gateway --capture-point wan=eth0

# Render nftables rules (does not apply them; v1 only)
ibn-monitor render-nftables --config config/policy.json --output build/ibn-monitor.nft

# Docker (requires Linux for live capture)
make docker                   # docker compose up --build -d
```

## Configuration

**V1** `config/policy.json` is validated against packaged `ibn_monitor/policy.schema.json`. Schema owns structure; `config.py` owns semantics (unique IDs, CIDR parse). `notifications.webhook_url_env` names an **environment variable** that holds the URL. SIGHUP reloads rules only.

**V2** `config/policy.v2.example.json` uses packaged `ibn_monitor/policy-v2.schema.json`. Selectors are explicit (no omitted-CIDR-means-any). Semantic diagnostics include mirror promiscuous requirements, duplicate IDs/interfaces, impossible IP families, and rule overlap warnings. Canonical `policy_revision` / `config_revision` are SHA-256 of normalized wire form.

## Testing Patterns

Tests live in `tests/`; conftest disables Scapy route auto-loading:

```python
# conftest.py — prevents Scapy from reading host routing table in CI
from scapy.config import conf

conf.route_autoload = False
conf.route6_autoload = False
```

Shared factories live in `tests/factories.py` (`rule`, `metadata`, `app_config`, `policy_rule`, `observation`, `v2_config`) with overridable defaults. Prefer importing those rather than duplicating helpers per test module:

```python
from factories import rule, metadata, app_config, policy_rule, observation, v2_config

r = rule(id="OTHER", action="alert")
pkt = metadata(destination_port=443)
cfg = app_config(tmp_path, (r,))
obs = observation(destination_port=443)
v2 = v2_config(rules=(policy_rule(id="R2"),))
```

Header-only packet/PCAP builders live in `tests/packet_bytes.py` and `tests/pcap_bytes.py` (stdlib only; no Scapy). Temporary config files use pytest's `tmp_path` fixture; no mocking of Scapy is needed for engine/config/v2 unit tests.

## Key Conventions

- **Frozen models everywhere**: `PacketMetadata` and `Rule` are `@dataclass(frozen=True, slots=True)`. Do not add mutable state to models.
- **Thread boundaries**: Only `WebhookNotifier` crosses thread boundaries; webhook POSTs go onto a `queue.Queue` consumed by a daemon thread. `PolicyEngine` uses `RLock` for atomic rule swap on reload.
- **`ConfigError` for validation failures**: Raise `ConfigError` (not `ValueError`) for any policy/config problem caught in `config.py`.
- **Metrics naming**: Prometheus counters follow `ibn_monitor_<noun>_total`; gauges use `ibn_monitor_<noun>` (see `events.py`).
- **No payload capture**: The sensor only extracts IP/transport header fields; never buffer or log packet payload bytes.
- **`action` semantics**: `alert` = detect and log only. `drop` = detect, log, AND eligible for nftables rendering. The sensor itself never drops packets; enforcement is a separate `render-nftables` step.

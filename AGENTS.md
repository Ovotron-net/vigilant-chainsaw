# AGENTS.md — ibn-monitor

Intent-Based Continuous Traffic Monitor: a Windows and Linux network sensor that captures IP header metadata (Windows raw IP / Linux AF_PACKET), evaluates it against declarative JSON policies, logs schema-v2 evidence as JSONL, optionally notifies via webhook, and can render v2 `nftables_drop_candidate` rules into topology-aware nftables.

## Architecture

| Module | Role |
|---|---|
| `models.py` | Frozen domain types: `Observation`, `PolicyRule`, episodes, evidence envelopes |
| `config.py` | V2 `validate_v2_config`/`load_v2_config` (one builder per section; defaults live on the dataclasses), `ConfigSource` (file + `--interface` override, same on reload), `runtime_identity_hash`, `is_loopback_host` |
| `capture.py` | `ObservationSource` seam; `CaptureSource` shared live lifecycle (thread, reconnect/backoff, decode fallback, stats) around a `CaptureAdapter`; `MemoryObservationSource` |
| `capture_live.py` | The one platform check + factory → Windows or Linux adapter |
| `capture_windows.py` / `windows_packet.py` | Windows `WindowsRawAdapter` (SIO_RCVALL, DLT_RAW) |
| `capture_afpacket.py` | Linux `AfPacketAdapter` (AF_PACKET, owned cBPF attached via `SO_ATTACH_FILTER`) |
| `cbpf.py` / `linux_packet.py` / `staged_reader.py` | Owned BPF templates, socket helpers, MSG_PEEK reader |
| `decode.py` / `pcap.py` / `policy.py` / `episodes.py` | Pure v2 decode, PCAP, match, episode tracking |
| `processing.py` | `EpisodeProcessor`: Observation/tick/reload/shutdown → sequenced evidence envelopes (no I/O); owns the reload contract |
| `replay.py` | Offline replay: PCAP watermark ordering around the Episode processor |
| `pipeline.py` / `ops_state.py` / `read_model.py` | Threaded worker (queues, control lane) around the Episode processor; ops state machine; `ReadModel.publish` — one atomic projection read by probe and ops HTTP |
| `probe.py` / `operations.py` / `dashboard.py` | Probe `/healthz` `/readyz` `/metrics`; ops `/` + `/api/state`; embedded SPA |
| `journal.py` / `notifications_v2.py` | Durable journal (`JournalWriter` satisfies `EvidenceWriter`), v2 webhooks (`V2Notifier.stats()`) |
| `monitor.py` | `LiveMonitor` composition root |
| `migration.py` / `cli.py` | Sole version 1 reader (v1→v2 migrate); validate/check/replay/run/render-nftables |
| `enforcement.py` | Topology-aware `render_nftables_v2` (gateway/host; mirror rejected) |
| `evidence.py` | `EvidenceSequencer` (sole sequence allocator), canonical `serialize_evidence`, `EvidenceWriter` seam + `MemoryEvidenceWriter` |

**Live data flow (v2):** capture adapter (Windows SIO_RCVALL or Linux AF_PACKET) → CaptureSource → decode → Observation queue → PipelineWorker → EpisodeProcessor (evaluate_policy → EpisodeTracker → EvidenceSequencer) → JournalWriter → WebhookV2Notifier → ops snapshot / probe.

**Offline:** `ibn-monitor replay` (classic PCAP, no admin). **Live:** Windows or Linux + policy version 2 (admin/CAP_NET_RAW).

## Essential Commands

```bash
pip install -e ".[dev]"
make test                 # excludes linux_raw / linux_perf markers
make lint
ruff format .             # CI-clean: ruff format --check .
make release-check        # lint + tests + microbench + validate + replay + wheel
make validate-v2
make replay-v2
make microbench
make nftables-v2
# Privileged Linux lab only:
# make test-linux-raw
ibn-monitor migrate-policy --config config/policy.json --output build/policy.v2.json \
  --sensor-id edge-gw-01 --topology gateway --capture-point wan=eth0
# Live Windows (Administrator; default config/policy.v2.windows.json):
ibn-monitor run
# Live Linux:
ibn-monitor run --config config/policy.v2.example.json
```

Operator docs: `docs/operator/runbook.md`, `migration-and-events.md`,
`release-checklist.md`, `ops-state-api.md`.

## Key Conventions

- Frozen models; no payload capture.
- Scapy is **not** a runtime dependency.
- Sequence allocation stays on `EvidenceSequencer` inside `EpisodeProcessor`; journal is durability only.
- Live and replay both go through `EpisodeProcessor`; never re-implement evaluate → episode → sequence elsewhere.
- SIGHUP reloads rules only when `runtime_identity_hash` is unchanged; reloads go through the same `ConfigSource` (overrides included) as startup.
- Raise `ConfigError` for config problems.
- The OS is checked only in `capture_live`; platform code lives behind `CaptureAdapter`.
- Health crosses interfaces (`EvidenceWriter.healthy`, `V2Notifier.stats()`); the worker publishes to `ReadModel` in one atomic `publish` call.

## Build & Setup

- **Python ≥ 3.11**. Single runtime dependency: `jsonschema>=4.18,<5`.
- Dev dependencies: `pytest>=8.3,<10`, `pytest-cov>=6,<8`, `ruff>=0.12,<1`.
- Editable install: `pip install -e ".[dev]"`; packages live under `src/` (`[tool.setuptools] package-dir`).
- Only `policy-v2.schema.json` ships as package data.

## Testing

```bash
pytest                              # default addopts exclude linux_raw / linux_perf, enable coverage
pytest -k processing                # keyword filter
pytest -m linux_raw -q --no-cov     # privileged Linux lab only (root + netns)
```

- Tests live flat in `tests/` (plus `tests/integration_linux/`); `conftest.py` only registers markers.
- `tests/factories.py`: `policy_rule(**overrides)`, `observation(**overrides)`, `v2_config(rules=...)`.
- `tests/packet_bytes.py` / `tests/pcap_bytes.py`: raw packet and classic-PCAP builders.
- Import factories directly: `from factories import observation, policy_rule, v2_config`.
- Test through the interface: `EpisodeProcessor` for evaluate/episode/sequence/reload behaviour,
  `CaptureSource` with a scripted adapter for capture lifecycle, real `ProbeServer` /
  `OperationsServer` on `ListenerV2Config(port=0)` for HTTP.
- `evaluate_policy(compile_policy(rules, revision), obs)` returns a tuple of matches (`.rule`).

## Code Style

- `ruff` rules `E, F, I, B, UP, SIM`; line length 100; `target-version = "py311"`.
- `dashboard.py` is exempt from E501 (embedded HTML/CSS asset).
- Frozen dataclasses; copy with `dataclasses.replace()`.
- `from __future__ import annotations` in every module.
- No Scapy at runtime or in tests — raw bytes and struct-based decoding only.

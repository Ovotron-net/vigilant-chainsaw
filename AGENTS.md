# AGENTS.md — ibn-monitor

Intent-Based Continuous Traffic Monitor: a Linux network sensor that captures IP header metadata via AF_PACKET, evaluates it against declarative JSON policies, logs schema-v2 evidence as JSONL, optionally notifies via webhook, and can render v1 `action=drop` rules into nftables.

## Architecture

| Module | Role |
|---|---|
| `models.py` | Frozen domain types: v2 `Observation`/`PolicyRule`/episodes/evidence; transitional v1 `Rule`/`Event` for render/check |
| `config.py` | V1 `load_config` (render/migrate source); v2 `validate_v2_config`/`load_v2_config` + `runtime_identity_hash` |
| `capture.py` | `ObservationSource` + `MemoryObservationSource` (no Scapy) |
| `capture_live.py` | Platform factory → Windows raw IP or Linux AF_PACKET |
| `capture_windows.py` / `windows_packet.py` | Windows `WindowsRawSource` (SIO_RCVALL, DLT_RAW) |
| `capture_afpacket.py` | Linux `AfPacketSource` (AF_PACKET / cBPF) |
| `cbpf.py` / `linux_packet.py` / `staged_reader.py` | Owned BPF templates, socket helpers, MSG_PEEK reader |
| `decode.py` / `pcap.py` / `policy.py` / `episodes.py` / `replay.py` | Pure v2 decode, PCAP, match, episodes, offline replay |
| `pipeline.py` / `ops_state.py` / `read_model.py` | Ordered worker, ops state, atomic operations projection |
| `probe.py` / `operations.py` / `dashboard.py` | Probe `/healthz` `/readyz` `/metrics`; ops `/` + `/api/state`; embedded SPA |
| `journal.py` / `notifications_v2.py` / `evidence_stub.py` | Durable journal, v2 webhooks, evidence writer seam |
| `monitor.py` | `LiveMonitor` composition root |
| `migration.py` / `cli.py` | v1→v2 migrate; validate/check/replay/run/render-nftables |
| `enforcement.py` | V1 `render_nftables` + v2 topology-aware `render_nftables_v2` (gateway/host; mirror rejected) |
| `engine.py` / `events.py` / `health.py` | V1 check/render helpers + legacy metrics |

**Live data flow (v2):** capture (Windows SIO_RCVALL or Linux AF_PACKET) → decode → Observation queue → PipelineWorker → evaluate_policy → EpisodeTracker → EvidenceSequencer → JournalWriter → WebhookV2Notifier → ops snapshot / probe.

**Offline:** `ibn-monitor replay` (classic PCAP, no admin). **Live:** Windows or Linux + policy version 2 (admin/CAP_NET_RAW).

## Essential Commands

```bash
pip install -e ".[dev]"
make test                 # excludes linux_raw / linux_perf markers
make lint
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
`release-checklist.md`, `docker.md`, `ops-state-api.md`.

Docker (Windows Desktop only): multi-stage `Dockerfile` + `compose.yaml` (bridge,
ports 9108/9109, no host net / no NET_RAW). Policy
`config/policy.v2.docker.json` binds `0.0.0.0` with ops `allow_non_loopback`.
Live capture stays degraded on Desktop; use validate/replay profiles or Linux
systemd for real sensing. Env: `IBN_CONFIG`, `IBN_WEBHOOK_URL`.

## Key Conventions

- Frozen models; no payload capture.
- Scapy is **not** a runtime dependency.
- Sequence allocation stays on `EvidenceSequencer` (worker); journal is durability only.
- SIGHUP reloads rules only when `runtime_identity_hash` is unchanged.
- Raise `ConfigError` for config problems.

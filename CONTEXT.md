# CONTEXT.md — ibn-monitor domain glossary

Shared vocabulary for the Intent-Based Continuous Traffic Monitor. Use these
terms exactly in code, tests, and docs.

## V1 (migration input only)

V1 policy files are accepted only by `migrate-policy`. Every other command
rejects `version: 1` and points at `migrate-policy`.

| Term | Meaning |
|---|---|
| **V1 rule** | Legacy policy entry read only by `migration.py`. |
| **Action** | V1 `alert` / `drop`; migrates to v2 enforcement disposition. The sensor never drops packets. |
| **Enforcement** | Separate topology-aware `render-nftables` step over a v2 policy. |

## V2 (Phase 1 core / replay)

| Term | Meaning |
|---|---|
| **Observation** | Immutable complete/partial/undecodable L3/L4 metadata record; replaces packet-shaped v1 metadata in v2. Never includes payload bytes. |
| **Policy rule** | Explicit prohibited-flow assertion (`PolicyRule`) with nested match selectors and enforcement disposition. |
| **Compiled policy** | Immutable normalized predicate IR (`CompiledPolicy`) with a canonical policy revision hash. |
| **Violation episode** | Rule-plus-flow lifecycle aggregation with start/progress/close transitions (`EpisodeTransition`). |
| **Evidence envelope** | Schema-v2 sequenced JSONL wrapper (`EvidenceEnvelope`) around episode transitions. |
| **Replay watermark** | Maximum seen capture time minus allowed lateness; orders event-time processing for classic PCAP replay. |
| **Diagnostic** | Structured validation warning/error with stable code, path, and message. |
| **Field presence** | Bit flags describing which Observation fields are known (`FieldPresence`). Partial observations never treat unknown constrained fields as wildcards. |
| **ObservationSource** | Live capture seam (`capture.ObservationSource`). Production: `CaptureSource` around a Capture adapter, built by `capture_live.build_live_sources`. Tests: `MemoryObservationSource`. |
| **Episode processor** | The one module that turns Observations, ticks, reloads and shutdowns into sequenced Evidence envelopes. It owns the Compiled policy, episode tracking, sequence allocation and the reload contract, and does no I/O. Live and replay are its two callers. |
| **Config source** | Produces the *effective* v2 config: file plus operator overrides such as `--interface`. The same overrides apply at startup and on every reload. |
| **Capture adapter** | Platform half of an ObservationSource (`CaptureAdapter`: Windows `WindowsRawAdapter`, Linux `AfPacketAdapter`): open, read one header, kernel stats, close. Lifecycle, reconnect and decode live in the shared `CaptureSource`. |
| **Evidence journal** | Durable append-only JSONL with rotation, fsync, emergency buffer (`journal.JournalWriter`). |
| **V2 notifier** | Webhook delivery of eligible evidence envelopes (`notifications_v2`). |

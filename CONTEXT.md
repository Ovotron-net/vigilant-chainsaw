# CONTEXT.md — ibn-monitor domain glossary

Shared vocabulary for the Intent-Based Continuous Traffic Monitor. Use these
terms exactly in code, tests, and docs.

## V1 (transitional render / migrate / synthetic check)

| Term | Meaning |
|---|---|
| **Rule** | V1 policy entry (`Rule`) used by `render-nftables` and `migrate-policy` input. |
| **Action** | `alert` / `drop` for v1 render eligibility. The sensor never drops packets. |
| **Enforcement** | Separate `render-nftables` step (v1 config until Phase 5 topology-aware renderer). |

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
| **ObservationSource** | Live capture seam (`capture.ObservationSource`). Production: Windows `WindowsRawSource` (SIO_RCVALL) or Linux `AfPacketSource` via `capture_live.build_live_sources`. Tests: `MemoryObservationSource`. |
| **Evidence journal** | Durable append-only JSONL with rotation, fsync, emergency buffer (`journal.JournalWriter`). |
| **V2 notifier** | Webhook delivery of eligible evidence envelopes (`notifications_v2`). |

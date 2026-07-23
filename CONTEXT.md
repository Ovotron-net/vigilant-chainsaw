# CONTEXT.md — ibn-monitor domain glossary

Shared vocabulary for the Intent-Based Continuous Traffic Monitor. Use these
terms exactly in code, tests, and docs.

## V1 (transitional live / render path)

| Term | Meaning |
|---|---|
| **Packet metadata** | The IP/transport header fields extracted from a captured packet (`PacketMetadata`). Never includes payload bytes. Transitional until Phase 2 live capture. |
| **Rule** | One declarative policy entry from v1 `policy.json`: CIDRs, protocol, ports, severity, action. Immutable (`Rule`). Transitional until Phase 2. |
| **Violation** | A packet whose metadata matches an enabled Rule. |
| **Event** | The immutable record of a Violation: identity, observed time, matched Rule summary, and Packet metadata. Persisted as schema-v1 JSONL; optionally delivered by webhook. |
| **Notifier** | The seam that optionally delivers Events outward (e.g. webhook). Owns suppress/dedup/drop policy for delivery; not responsible for JSONL persistence. |
| **Action** | `alert` = detect and log only. `drop` = detect, log, and eligible for nftables rendering. The sensor itself never drops packets. |
| **PacketSource** | The seam between packet capture and the monitor loop (`capture.PacketSource`, a `typing.Protocol`). Pushes `PacketMetadata \| None` (`None` = undecodable) to a callback. `start(callback)` returns when capture is established (live) or exhausted (finite). |
| **Capture adapter** | An implementation behind the PacketSource seam. Production: `ScapyLiveSource` (AsyncSniffer), `PcapReplaySource` (offline replay). Tests: in-memory source pushing canned metadata. All Scapy imports live in `capture.py`. |
| **Enforcement** | The separate `render-nftables` step that turns `action=drop` Rules into an nftables ruleset. Not part of the live sensor loop. |

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

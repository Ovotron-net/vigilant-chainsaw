# CONTEXT.md — ibn-monitor domain glossary

Shared vocabulary for the Intent-Based Continuous Traffic Monitor. Use these
terms exactly in code, tests, and docs.

| Term | Meaning |
|---|---|
| **Packet metadata** | The IP/transport header fields extracted from a captured packet (`PacketMetadata`). Never includes payload bytes. |
| **Rule** | One declarative policy entry from `policy.json`: CIDRs, protocol, ports, severity, action. Immutable (`Rule`). |
| **Violation** | A packet whose metadata matches an enabled Rule. |
| **Event** | The immutable record of a Violation: identity, observed time, matched Rule summary, and Packet metadata. Persisted as JSONL; optionally delivered by webhook. |
| **Notifier** | The seam that optionally delivers Events outward (e.g. webhook). Owns suppress/dedup/drop policy for delivery; not responsible for JSONL persistence. |
| **Action** | `alert` = detect and log only. `drop` = detect, log, and eligible for nftables rendering. The sensor itself never drops packets. |
| **PacketSource** | The seam between packet capture and the monitor loop (`capture.PacketSource`, a `typing.Protocol`). Pushes `PacketMetadata \| None` (`None` = undecodable) to a callback. `start(callback)` returns when capture is established (live) or exhausted (finite). |
| **Capture adapter** | An implementation behind the PacketSource seam. Production: `ScapyLiveSource` (AsyncSniffer), `PcapReplaySource` (offline replay). Tests: in-memory source pushing canned metadata. All Scapy imports live in `capture.py`. |
| **Enforcement** | The separate `render-nftables` step that turns `action=drop` Rules into an nftables ruleset. Not part of the live sensor loop. |

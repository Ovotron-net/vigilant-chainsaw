# Policy migration and event schema mapping

## Migrating policy v1 → v2

```bash
ibn-monitor migrate-policy \
  --config config/policy.json \
  --output build/policy.v2.json \
  --sensor-id edge-gw-01 \
  --topology gateway \
  --capture-point wan=eth0

ibn-monitor validate --config build/policy.v2.json --strict
```

### Field mapping

| v1 | v2 | Notes |
|---|---|---|
| `version: 1` | `version: 2` | Required |
| (implicit any CIDR) | **rejected** | Must write explicit `/0` or real CIDRs |
| `source_cidrs` / `destination_cidrs` | `match.source_cidrs` / `match.destination_cidrs` | Nested under `match` |
| `protocol` | `match.protocol` | `any` \| `tcp` \| `udp` \| `icmp` |
| omitted ports (tcp/udp) | **rejected** | Use `"destination_ports": "any"` or list |
| `destination_ports: [...]` | `match.destination_ports` | Array or `"any"` |
| `action: alert` | `enforcement: none` | Detection only |
| `action: drop` | `enforcement: nftables_drop_candidate` | Render-eligible; sensor never drops |
| `severity` | `severity` | Same enum |
| `sensor.interface` | `sensor.capture_points[]` | Named points + topology |
| `sensor.bpf_filter` | **removed** | Owned cBPF only; non-default BPF refused |
| `logging.*` | `journal.*` | Same keys where present |
| `health.*` | `http.probe.*` | Ops listener is separate (9109) |
| `notifications.deduplication_seconds` | **removed** | Episode aggregation replaces per-packet dedup |
| `notifications.webhook_url_env` | same | Still env **name**, not URL |

Migration never overwrites the input file and refuses ambiguous selectors.

## Event schemas

### Schema v1 (legacy; not emitted by v2 live/replay)

Per-packet `network_policy_violation` with `rule` + `network` objects.

### Schema v2 evidence envelope

Every JSONL line / webhook body:

```json
{
  "schema_version": 2,
  "event_id": "<boot_id>:<sequence>",
  "event_type": "violation_episode" | "system.<name>",
  "sensor_id": "...",
  "boot_id": "...",
  "sequence": 1,
  "emitted_at": "ISO-8601",
  "policy_revision": "sha256-hex-or-null",
  "payload": { }
}
```

#### `event_type: violation_episode`

| Field | Meaning |
|---|---|
| `payload.phase` | `start` \| `progress` \| `close` |
| `payload.rule` | id, description, severity, enforcement |
| `payload.flow` | L3/L4 identity + `fields` mask + decode_reason |
| `payload.observation_count` / `observed_bytes` | Exact totals (not unique packets) |
| `payload.per_capture_point` | Per-point breakdown |
| `payload.close_reason` | `idle`, `capacity_evicted`, `policy_reload`, `source_exhausted`, `shutdown` |

Webhook eligibility: **start** and **close** only (plus severity gate). Progress is local/journal only.

#### System events (selected)

| `event_type` | When |
|---|---|
| `system.source_established` / `failed` / `retrying` / `recovered` / `stopped` | Capture lifecycle |
| `system.policy_reload_success` / `noop` / `failed` | SIGHUP outcomes |
| `system.coverage_gap` | After drop incidents recover |
| `system.kernel_drops_observed` | Kernel drop delta |

v2 does **not** emit a parallel per-packet violation stream. Consumers must aggregate on episodes.

## Consumer migration tips

1. Key alerts on `(sensor_id, episode_id, phase)` not packet timestamps alone.
2. Treat `observation_count` growth between start and close as volume, not new incidents.
3. Use `policy_revision` for config drift detection.
4. Prefer journal shipping over relying solely on webhooks (journal is authoritative).

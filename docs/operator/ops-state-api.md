# Operations state API (`GET /api/state`)

Read-only atomic snapshot served by the **operations** HTTP listener
(default `127.0.0.1:9109`). Consumed by the embedded dashboard
(`src/ibn_monitor/dashboard.py`).

Day-2 ports and incidents: [runbook.md](runbook.md).
Probe vs ops migration: [migration-and-events.md](migration-and-events.md).

## Producer (source of truth)

| Piece | Location |
|---|---|
| Snapshot assembly | `ReadModel.view()` in `src/ibn_monitor/read_model.py` |
| Episode summaries | `episode_summary()` (same module) |
| Rule projection | `rule_to_dict()` (same module) |
| Evidence wire shape | `EvidenceEnvelope.to_dict()` in `src/ibn_monitor/models.py` |
| HTTP transport | `OperationsServer` in `src/ibn_monitor/operations.py` |
| Smoke coverage (partial) | `tests/test_operations_v2.py` — counters/metrics smoke, not a full key lock |

Additive top-level or nested fields are non-breaking for clients that ignore
unknown keys. Removing or renaming keys is breaking for ops UIs — update
fixtures/tests and note it in release notes.

## Trust boundary

- Loopback by default: bind to a loopback **IP literal** such as `127.0.0.1` or
  `::1`. Config validation uses `ip_address(...).is_loopback`; hostnames
  (including `localhost`) are **not** treated as loopback and require
  `allow_non_loopback=true`.
- Non-loopback bind requires explicit `http.operations.allow_non_loopback=true`
  (validated at config load and again at server start).
- No authentication on the sensor.
- No state-changing routes (`GET` only).
- Strict security headers: `Cache-Control: no-store`, `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, restrictive CSP.
- Probe endpoints (`/healthz`, `/readyz`, `/metrics`) are on a **separate**
  listener (default `:9108`). They are not aliases of this API.
- No CORS headers; prefer same-origin or a reverse proxy.

## Routes (operations listener)

| Path | Response |
|---|---|
| `GET /` | Embedded HTML dashboard |
| `GET /api/state` | JSON snapshot (this document) |
| other | `404` `{"error":"not_found"}` |

## Top-level response

Illustrative full body:
[fixtures/ops-state.example.json](fixtures/ops-state.example.json).

| Key | Type | Description |
|---|---|---|
| `operational` | object | Readiness, revisions, queue, drops, per-source capture status |
| `totals` | object | Pipeline counters since process start |
| `rules` | array | Loaded v2 policy rules (projection, not raw config file) |
| `active_episodes` | array | Up to 100 active episode summaries |
| `active_episodes_truncated` | bool | `true` if more than 100 actives existed at snapshot time |
| `recent_events` | array | Up to 100 evidence envelopes (ring, oldest → newest) |
| `recent_events_truncated` | bool | `true` once the recent-events ring has wrapped |
| `journal` | object | Journal writer health |
| `notifier` | object | Webhook delivery counters |

## Nested fields

### `operational`

| Key | Type | Notes |
|---|---|---|
| `state` | string | `starting` \| `ready` \| `degraded` \| `stopping` |
| `ready` | bool | `true` only when `state == "ready"` |
| `reasons` | string[] | Sorted reason codes (empty when healthy-ready) |
| `policy_revision` | string \| null | Loaded policy hash |
| `config_revision` | string \| null | Runtime-identity hash (reload gate) |
| `sensor_id` | string | From config |
| `boot_id` | string | Process boot identity |
| `queue_depth` | int | Current observation queue depth |
| `queue_capacity` | int | Configured capacity |
| `app_queue_drops_total` | int | Application queue drops |
| `kernel_drops_total` | int | Aggregated kernel drops |
| `sources` | array | Per capture-point status (see below) |

When ops has never published a snapshot, `view()` still returns defaults
(`state: "starting"`, empty `sources`, zero queues).

#### `operational.sources[]`

| Key | Type | Notes |
|---|---|---|
| `capture_point` | string | Logical name (e.g. `wan`) |
| `interface` | string | OS interface |
| `state` | string | `starting` \| `established` \| `failed` \| `retrying` \| `stopped` |
| `source_generation` | string \| null | Generation id while established |
| `last_error` | string \| null | Last failure detail |
| `kernel_packets` | int | Kernel receive counter |
| `kernel_drops` | int | Kernel drop counter |

### `totals`

| Key | Type |
|---|---|
| `observations` | int |
| `complete` | int |
| `partial` | int |
| `undecodable` | int |
| `matched_observations` | int |
| `rule_matches` | int |
| `episodes_started` | int |
| `episodes_progressed` | int |
| `episodes_closed` | int |

### `rules[]`

| Key | Type | Notes |
|---|---|---|
| `id` | string | |
| `description` | string | |
| `enabled` | bool | |
| `match.source_cidrs` | string[] | CIDR text |
| `match.destination_cidrs` | string[] | CIDR text |
| `match.protocol` | string | `any` \| `tcp` \| `udp` \| `icmp` |
| `match.destination_ports` | int[] \| `"any"` | Sorted ints, or the string `"any"` |
| `severity` | string | `low` \| `medium` \| `high` \| `critical` |
| `enforcement` | string | `none` \| `nftables_drop_candidate` |

### `active_episodes[]`

Summaries (not full evidence envelopes). Cap 100; see
`active_episodes_truncated`.

| Key | Type | Notes |
|---|---|---|
| `episode_id` | string | |
| `phase` | string | `start` \| `progress` \| `close` |
| `rule_id` | string | |
| `severity` | string | |
| `enforcement` | string | |
| `source` | string \| null | |
| `destination` | string \| null | |
| `protocol` | string \| null | |
| `destination_port` | int \| null | |
| `observation_count` | int | |
| `observed_bytes` | int | |
| `first_observed_at` | string | ISO-8601 |
| `last_observed_at` | string | ISO-8601 |
| `close_reason` | string \| null | Present on close phases |

### `recent_events[]`

Full schema-v2 evidence envelopes via `EvidenceEnvelope.to_dict()`.
Ring buffer (default maxlen 100); oldest → newest. See
`recent_events_truncated`.

Envelope keys:

| Key | Type |
|---|---|
| `schema_version` | int (2) |
| `event_id` | string |
| `event_type` | string |
| `sensor_id` | string |
| `boot_id` | string |
| `sequence` | int |
| `emitted_at` | string (ISO-8601) |
| `policy_revision` | string \| null |
| `payload` | object | Either violation episode or system event |

**Violation episode** `payload` includes `episode_id`, `phase`, `rule`, `flow`,
timestamps, counters, `per_capture_point`, `truncated`, `close_reason`.

**System** `payload` includes `name` plus event-specific fields
(e.g. sensor lifecycle).

Wire mapping for journal/webhooks is the same envelope shape; see
[migration-and-events.md](migration-and-events.md).

### `journal`

| Key | Type | Notes |
|---|---|---|
| `healthy` | bool | Writer can append / not in hard-fail |

### `notifier`

| Key | Type | Notes |
|---|---|---|
| `sent` | int | Successful webhook deliveries |
| `failed` | int | Delivery failures |
| `dropped` | int | Queue drops |
| `suppressed` | int | Severity/eligibility suppressions |

## Client guidance

- Poll every 1–3s; treat each body as one atomic snapshot.
- On transient fetch failures, keep the previous UI snapshot when possible.
- Show truncation banners when `active_episodes_truncated` or
  `recent_events_truncated` is true.
- Prefer same-origin or a reverse proxy; the sensor does not send CORS headers.
- Do not assume `/api/state` is on the probe port (`9108`).

## Example consumer (in-tree)

- Embedded dashboard: `src/ibn_monitor/dashboard.py` (3s `fetch("/api/state")` + DOM render)

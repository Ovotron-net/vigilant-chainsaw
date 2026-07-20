# Event / Notifier Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align code with the domain glossary (typed `Event`, separate **Notifier** seam), delete dual config validation and dual schema copies, and tighten test/API boundaries — without changing runtime behavior of capture, policy matching, JSONL shape, webhooks, health, or the dashboard.

**Architecture:** Keep the ten-module map under `src/ibn_monitor/`. Introduce a frozen `Event` next to `Rule` / `PacketMetadata`. Split `EventDispatcher` into (1) JSONL + recent ring and (2) a `Notifier` Protocol with a webhook implementation (and no-op when unset). Collapse `config.py` so JSON Schema owns structural validation; Python only does CIDR parse, unique IDs, cross-field rules, and dataclass construction. Single schema source of truth packaged under `ibn_monitor`.

**Tech Stack:** Python 3.11+, stdlib (dataclasses, threading, queue, http.server), `jsonschema`, `scapy` (untouched), pytest/ruff.

## Global Constraints

- Behavior-preserving refactor: JSONL event JSON keys, Prometheus metric names, CLI exit codes, nftables output, and `/api/state` JSON shape stay compatible.
- Frozen models only for domain records (`frozen=True, slots=True`).
- Raise `ConfigError` (not bare `ValueError`) for policy/config failures.
- Thread boundary: only the Notifier webhook worker crosses threads (same as today).
- No payload capture; sensor stays header-only.
- No new runtime dependencies.
- Prefer deleting code over adding wrappers.
- Tests: `make test` and `make lint` green after every PR.
- Update `AGENTS.md`, `CONTEXT.md`, and `README.md` architecture tables when module responsibilities change.

---

## Target shape (after all PRs)

```text
PacketSource → PacketMetadata | None
  → PolicyEngine.evaluate → list[Rule]
  → Event = create_event(packet, rule)     # frozen model
  → EventLog.write(event)                  # JSONL + recent ring + metrics.mark_violation already done in MonitorService
  → Notifier.notify(event)                 # Protocol; NullNotifier | WebhookNotifier
```

| Module | Responsibility after refactor |
|---|---|
| `models.py` | `PacketMetadata`, `Rule`, **`Event`** (+ small serialization helpers if needed) |
| `events.py` | `Metrics`, `EventLog` (JSONL + recent), `Notifier` Protocol, `WebhookNotifier`, `NullNotifier`, `create_event` |
| `monitor.py` | Compose engine + event log + notifier + health |
| `config.py` | Schema validate + semantic construct only |
| `health.py` | HTTP; required state providers; serializes models to JSON |

Legacy name `EventDispatcher` is **removed** (not aliased) once call sites are updated in the same PR.

---

## File map

| Path | PR1 | PR2 | PR3 | PR4 |
|---|---|---|---|---|
| `src/ibn_monitor/models.py` | modify | | | |
| `src/ibn_monitor/events.py` | modify | major rewrite | | |
| `src/ibn_monitor/monitor.py` | | modify | | modify |
| `src/ibn_monitor/health.py` | modify | modify | | modify |
| `src/ibn_monitor/cli.py` | | | | modify |
| `src/ibn_monitor/config.py` | | | rewrite | |
| `src/ibn_monitor/policy.schema.json` | | | keep (SSOT) | |
| `config/policy.schema.json` | | | delete or stub→point to package | |
| `tests/conftest.py` | | | | expand factories |
| `tests/test_*.py` | touch | touch | touch | consolidate |
| `CONTEXT.md` / `AGENTS.md` / `README.md` | light | update | light | light |

---

## PR order and dependency graph

```text
PR1  Typed Event model (+ wire serialize edges)
  │
  ▼
PR2  Split EventLog / Notifier; delete EventDispatcher
  │
  ▼
PR3  Collapse dual config validation + single schema SSOT
  │
  ▼
PR4  API / reload / conftest cleanup (can merge into PR2 if small)
```

Ship one PR at a time. Each must be independently mergeable and green.

---

# PR1 — Frozen `Event` model

**Goal:** Domain event is a real immutable type; JSON shape at the wire stays identical.

**Architecture note:** Keep `create_event` in `events.py` (or move to `models.py` if you prefer colocation). Prefer putting `Event` + nested summary types in `models.py` to match “frozen models everywhere.”

### Task 1: Add `Event` model and failing serialization tests

**Files:**
- Modify: `src/ibn_monitor/models.py`
- Create: `tests/test_events.py` (or extend if one exists)
- Modify: `CONTEXT.md` (commit the Notifier glossary lines if still uncommitted — docs only for Notifier until PR2)

**Interfaces:**
- Produces:

```python
@dataclass(frozen=True, slots=True)
class Event:
    schema_version: int
    event_id: str
    event_type: str
    observed_at: str
    rule_id: str
    rule_description: str
    rule_severity: Severity
    rule_action: Action
    network: PacketMetadata

    def to_dict(self) -> dict[str, object]:
        """Wire format for JSONL / webhook /api/state — same keys as today."""
        ...
```

Wire shape **must** remain:

```json
{
  "schema_version": 1,
  "event_id": "...",
  "event_type": "network_policy_violation",
  "observed_at": "...",
  "rule": {"id": "...", "description": "...", "severity": "...", "action": "..."},
  "network": { /* asdict(PacketMetadata) */ }
}
```

- [ ] **Step 1: Write the failing test**

```python
# tests/test_events.py
from ibn_monitor.events import create_event
from ibn_monitor.models import Event, PacketMetadata, Rule
from ipaddress import ip_network


def _rule(**overrides):
    base = dict(
        id="R1",
        description="test",
        enabled=True,
        source_cidrs=(ip_network("10.0.0.0/8"),),
        destination_cidrs=(),
        protocol="tcp",
        destination_ports=frozenset({443}),
        severity="high",
        action="alert",
    )
    base.update(overrides)
    return Rule(**base)


def _packet(**overrides):
    base = dict(
        timestamp="2026-01-01T00:00:00+00:00",
        interface="eth0",
        source="10.1.2.3",
        destination="10.9.8.7",
        protocol="tcp",
        source_port=40000,
        destination_port=443,
    )
    base.update(overrides)
    return PacketMetadata(**base)


def test_create_event_returns_frozen_event():
    event = create_event(_packet(), _rule())
    assert isinstance(event, Event)
    assert event.rule_id == "R1"
    assert event.network.destination_port == 443


def test_event_to_dict_matches_legacy_wire_shape():
    event = create_event(_packet(), _rule())
    payload = event.to_dict()
    assert payload["schema_version"] == 1
    assert payload["event_type"] == "network_policy_violation"
    assert payload["rule"] == {
        "id": "R1",
        "description": "test",
        "severity": "high",
        "action": "alert",
    }
    assert payload["network"]["source"] == "10.1.2.3"
    assert "event_id" in payload and payload["event_id"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_events.py -v
```

Expected: FAIL (create_event returns dict / Event missing).

- [ ] **Step 3: Implement `Event` + `to_dict` + update `create_event`**

```python
# models.py (add)
@dataclass(frozen=True, slots=True)
class Event:
    schema_version: int
    event_id: str
    event_type: str
    observed_at: str
    rule_id: str
    rule_description: str
    rule_severity: Severity
    rule_action: Action
    network: PacketMetadata

    def to_dict(self) -> dict[str, object]:
        from dataclasses import asdict
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "observed_at": self.observed_at,
            "rule": {
                "id": self.rule_id,
                "description": self.rule_description,
                "severity": self.rule_severity,
                "action": self.rule_action,
            },
            "network": asdict(self.network),
        }
```

```python
# events.py create_event
def create_event(packet: PacketMetadata, rule: Rule) -> Event:
    return Event(
        schema_version=1,
        event_id=str(uuid.uuid4()),
        event_type="network_policy_violation",
        observed_at=packet.timestamp,
        rule_id=rule.id,
        rule_description=rule.description,
        rule_severity=rule.severity,
        rule_action=rule.action,
        network=packet,
    )
```

- [ ] **Step 4: Update `EventDispatcher` internals to accept `Event` but write `event.to_dict()`**

Keep class name for this PR only if needed to minimize churn; prefer updating signatures now:

```python
def emit(self, event: Event) -> None:
    payload = event.to_dict()
    self._event_logger.write(payload)
    with self._recent_lock:
        self._recent.append(payload)  # store dicts for API compatibility
    ...
    # webhook path uses payload; severity from event.rule_severity
```

`_send_if_required` should use `event.rule_severity` and `event.network` fields (or payload) — prefer typed fields for severity/dedup key.

Dedup key construction from typed fields:

```python
key = ":".join(
    str(v)
    for v in (
        event.rule_id,
        event.network.source,
        event.network.destination,
        event.network.protocol,
        event.network.destination_port,
    )
)
```

- [ ] **Step 5: Fix health/events_provider types**

```python
# health.py — recent events remain list[dict] on the wire for this PR
EventsProvider = Callable[[], list[dict[str, Any]]]
```

If `recent_events()` still returns dicts, dashboard needs no JS changes.

- [ ] **Step 6: Run full suite**

```bash
make test
make lint
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/ibn_monitor/models.py src/ibn_monitor/events.py src/ibn_monitor/health.py tests/test_events.py CONTEXT.md
git commit -m "refactor: introduce frozen Event model with stable wire format"
```

### PR1 acceptance checklist

- [ ] `create_event` returns `Event`, not `dict`
- [ ] JSONL lines and webhook bodies still nest `rule` / `network` as today
- [ ] Dashboard still renders (poll `/api/state` shape unchanged)
- [ ] No new public modules; `models.py` remains the domain home
- [ ] `make test` + `make lint` green

---

# PR2 — Split EventLog / Notifier; delete EventDispatcher

**Goal:** Implement the glossary: persistence is not notification. Delete the grab-bag dispatcher.

### Task 2: Define Notifier Protocol + NullNotifier + WebhookNotifier tests

**Files:**
- Rewrite: `src/ibn_monitor/events.py`
- Modify: `src/ibn_monitor/monitor.py`
- Modify: `src/ibn_monitor/health.py` (if needed)
- Modify: `tests/test_monitor.py`, `tests/test_health.py`, `tests/test_events.py`
- Modify: `AGENTS.md`, `README.md`, `CONTEXT.md`

**Interfaces:**

```python
class Notifier(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def notify(self, event: Event) -> None: ...


class NullNotifier:
    """No-op when webhook_url_env is unset or empty."""
    def start(self) -> None: return
    def stop(self) -> None: return
    def notify(self, event: Event) -> None: return


class WebhookNotifier:
    def __init__(self, config: NotificationConfig, metrics: Metrics) -> None: ...
    # owns: queue, daemon thread, dedup map, severity gate, stop Event
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def notify(self, event: Event) -> None: ...  # put_nowait; drop on Full


class EventLog:
    def __init__(self, logging_config: LoggingConfig, *, recent_maxlen: int = 50) -> None: ...
    def write(self, event: Event) -> None:
        """Append JSONL line and push to recent ring as event.to_dict()."""
    def recent(self) -> list[dict[str, object]]: ...
    def close(self) -> None: ...


def build_notifier(config: NotificationConfig, metrics: Metrics) -> Notifier:
    """Return NullNotifier if webhook env name unset; else WebhookNotifier."""
```

Monitor composition:

```python
class MonitorService:
    def __init__(self, config: AppConfig, source: PacketSource) -> None:
        self.config = config
        self.source = source
        self.engine = PolicyEngine(config.rules)
        self.metrics = Metrics()
        self.event_log = EventLog(config.logging)
        self.notifier = build_notifier(config.notifications, self.metrics)
        self.health = HealthServer(
            config.health,
            self.metrics,
            rules_provider=self.engine.snapshot,
            events_provider=self.event_log.recent,
        )

    def start(self) -> None:
        try:
            self.notifier.start()
            self.health.start()
            ...
            self.source.start(self.on_packet, on_established=lambda: self.metrics.set_ready(True))
        except Exception:
            self.stop()
            raise

    def on_packet(self, metadata: PacketMetadata | None) -> None:
        self.metrics.mark_packet(decoded=metadata is not None)
        if metadata is None:
            return
        for rule in self.engine.evaluate(metadata):
            self.metrics.mark_violation()
            event = create_event(metadata, rule)
            self.event_log.write(event)
            self.notifier.notify(event)

    def stop(self) -> None:
        self.metrics.set_ready(False)
        self.source.stop()
        self.health.stop()
        self.notifier.stop()
        self.event_log.close()
```

- [ ] **Step 1: Write failing tests for NullNotifier and queue-drop metrics**

```python
# tests/test_events.py (add)

def test_null_notifier_does_not_raise():
    n = NullNotifier()
    n.start()
    n.notify(create_event(_packet(), _rule()))
    n.stop()


def test_event_log_writes_jsonl_and_recent(tmp_path):
    from ibn_monitor.config import LoggingConfig
    log = EventLog(LoggingConfig(file=str(tmp_path / "e.jsonl"), max_bytes=1024, backup_count=1))
    event = create_event(_packet(), _rule())
    log.write(event)
    log.close()
    lines = (tmp_path / "e.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["rule"]["id"] == "R1"
    assert log.recent()[0]["rule"]["id"] == "R1"
```

Note: after `close()`, `recent()` should still return the in-memory ring (or document that recent is available until process exit — prefer ring survives close; only handlers close).

- [ ] **Step 2: Implement EventLog, Notifier types; delete EventDispatcher**

Move webhook worker code almost verbatim from current `_worker` / `_send_if_required` into `WebhookNotifier`. Keep:

- queue maxsize 1000
- stop via `threading.Event` + sentinel `None`
- severity gate via `SEVERITY_ORDER`
- dedup window + prune at > 10_000 keys
- metrics: `notifications_sent`, `notification_failures`, `notifications_suppressed`, `notification_queue_dropped`

Factory:

```python
def build_notifier(config: NotificationConfig, metrics: Metrics) -> Notifier:
    if not config.webhook_url_env:
        return NullNotifier()
    return WebhookNotifier(config, metrics)
```

**Do not** early-return on missing env var at process start only — current code re-reads `os.getenv` per send. Preserve that: `WebhookNotifier` still checks env on each send if you keep runtime URL injection; if env name is set but value empty, skip send (same as today).

- [ ] **Step 3: Update MonitorService; remove all `EventDispatcher` references**

Grep for `EventDispatcher` / `dispatcher` and delete.

- [ ] **Step 4: Update AGENTS.md / README architecture table**

```markdown
| `events.py` | `Metrics`, `EventLog` (JSONL + recent ring), `Notifier` seam (`NullNotifier` / `WebhookNotifier`). |
```

Data flow line:

```markdown
… → `create_event()` → `EventLog.write()` + `Notifier.notify()` → JSONL + optional webhook + metrics.
```

- [ ] **Step 5: Run suite + manual smoke (optional)**

```bash
make test
make lint
ibn-monitor check --config config/policy.json --source 10.20.5.14 --destination 10.50.10.8 --protocol tcp --destination-port 5432
```

- [ ] **Step 6: Commit**

```bash
git commit -m "refactor: split EventLog and Notifier; remove EventDispatcher"
```

### PR2 acceptance checklist

- [ ] No symbol `EventDispatcher` in repo
- [ ] `CONTEXT.md` **Notifier** definition matches a real Protocol/type
- [ ] Webhook dedup / severity / queue-full metrics still work (cover with unit tests if not already)
- [ ] Health `/api/state` recent events still list dicts newest-append order (dashboard still reverses)
- [ ] Thread boundary: only webhook worker thread for I/O
- [ ] `make test` + `make lint` green

---

# PR3 — Collapse dual config validation + schema SSOT

**Goal:** Schema is structural truth; Python only does semantic construction. One schema file.

### Task 3: Shrink `load_config` + fail tests that still need semantic errors

**Files:**
- Rewrite: `src/ibn_monitor/config.py`
- Possibly enhance: `src/ibn_monitor/policy.schema.json` (add `if`/`then` for ports vs protocol)
- Delete or replace: `config/policy.schema.json`
- Modify: `tests/test_config.py`
- Modify: `AGENTS.md` (schema path wording)
- Modify: `README.md` if it references dual paths

**Keep in Python after schema:**

1. `ip_network(..., strict=False)` for each CIDR → `ConfigError` on parse failure  
2. Unique rule IDs  
3. Ports + non-tcp/udp rejection if not fully expressible in schema  
4. Build frozen `AppConfig` / nested configs / `Rule`

**Delete after schema owns them:**

- Redundant `_integer` / `_number` / `_string` range checks that mirror schema mins/maxes (keep thin helpers only if they improve error messages for construction)
- Re-checking protocol/severity/action enums after schema  
- Re-checking `version == 1` after schema `const: 1`

**Schema enhancement (recommended in same PR):**

```json
"if": {
  "properties": { "protocol": { "enum": ["icmp", "any"] } }
},
"then": {
  "properties": {
    "destination_ports": { "maxItems": 0 }
  }
}
```

(Or separate if/then for `any` if empty ports already default — match current Python: ports only allowed for tcp/udp.)

**SSOT:**

- Canonical file: `src/ibn_monitor/policy.schema.json` (already in `package-data`)
- Remove `config/policy.schema.json` **or** replace with a short README note in `config/` that the schema lives in the package. Prefer delete + doc update to avoid twins.
- Runtime continues: `resources.files("ibn_monitor").joinpath("policy.schema.json")`

Literal parsing without `type: ignore`:

```python
_PROTOCOLS: frozenset[str] = frozenset({"any", "tcp", "udp", "icmp"})

def _as_protocol(value: str, path: str) -> Protocol:
    if value not in _PROTOCOLS:
        raise ConfigError(f"{path} is invalid")
    return value  # type: ignore[return-value]  # avoid if using cast
```

Prefer:

```python
from typing import cast
return cast(Protocol, value)
```

after membership check (one cast site, not three ignore comments).

- [ ] **Step 1: Add/adjust tests**

Existing tests to keep green:

- `test_loads_valid_configuration`
- `test_rejects_ports_for_icmp`
- `test_rejects_unknown_top_level_key`
- `test_rejects_missing_version`
- `test_rejects_duplicate_destination_ports`

Add:

```python
def test_rejects_duplicate_rule_ids(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": 1,
        "rules": [{"id": "x"}, {"id": "x"}],
    }))
    with pytest.raises(ConfigError, match="unique"):
        load_config(path)


def test_rejects_invalid_cidr(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": 1,
        "rules": [{"id": "x", "source_cidrs": ["not-a-cidr"]}],
    }))
    with pytest.raises(ConfigError, match="CIDR"):
        load_config(path)
```

- [ ] **Step 2: Implement slim `load_config`**

Sketch:

```python
def load_config(path: str | Path) -> AppConfig:
    raw = _read_json(path)
    _validate_schema(raw)
    data = raw  # schema guarantees object
    sensor = _sensor(data.get("sensor", {}))
    logging_config = _logging(data.get("logging", {}))
    health = _health(data.get("health", {}))
    notifications = _notifications(data.get("notifications", {}))
    rules = _rules(data["rules"])
    return AppConfig(
        version=1,
        sensor=sensor,
        logging=logging_config,
        health=health,
        notifications=notifications,
        rules=rules,
    )
```

Use defaults when keys omitted (schema does not apply Python defaults — preserve current defaults for missing optional sections).

- [ ] **Step 3: Remove dual schema file; update docs**

AGENTS.md:

```markdown
`policy.json` is validated against the packaged schema `ibn_monitor/policy.schema.json` at startup.
```

- [ ] **Step 4: `make test` + `make lint`**

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor: schema-first config load; single policy schema source"
```

### PR3 acceptance checklist

- [ ] One schema file only under version control (package path)
- [ ] `config.py` line count materially down; no parallel enum/range re-validation for schema-owned fields
- [ ] Invalid CIDR and duplicate IDs still raise `ConfigError`
- [ ] icmp + ports still rejected
- [ ] Unknown top-level keys still rejected (schema `additionalProperties: false`)
- [ ] `make test` + `make lint` green

---

# PR4 — Boundary cleanup (small, can fold into PR2 if desired)

**Goal:** Explicit APIs; one test factory; no silent optionality.

### Task 4a: Required health providers + typed reload

**Files:**
- Modify: `src/ibn_monitor/health.py`
- Modify: `src/ibn_monitor/monitor.py`
- Modify: `src/ibn_monitor/cli.py`
- Modify: `src/ibn_monitor/engine.py` (if reload API already sufficient)

```python
# health.py — required, no None defaults
def __init__(
    self,
    config: HealthConfig,
    metrics: Metrics,
    rules_provider: RulesProvider,
    events_provider: EventsProvider,
) -> None: ...
```

```python
# monitor.py
def reload_rules(self, rules: tuple[Rule, ...]) -> None:
    self.engine.replace_rules(rules)
    logging.getLogger(__name__).info("Reloaded %d policy rules", len(rules))
```

```python
# cli.py SIGHUP path
reloaded = load_config(args.config)
service.reload_rules(reloaded.rules)
```

- [ ] Update tests that construct `HealthServer` to pass both providers
- [ ] Commit: `refactor: require health state providers; reload rules only`

### Task 4b: Shared test factories in conftest

**Files:**
- Modify: `tests/conftest.py`
- Modify: `tests/test_engine.py`, `test_enforcement.py`, `test_health.py`, `test_monitor.py` (remove local `rule()` / `app_config` / `metadata` duplicates)

```python
# tests/conftest.py
import pytest
from ipaddress import ip_network
from ibn_monitor.config import (
    AppConfig, HealthConfig, LoggingConfig, NotificationConfig, SensorConfig,
)
from ibn_monitor.models import PacketMetadata, Rule


@pytest.fixture
def rule_factory():
    def rule(**overrides):
        values = dict(
            id="DEV-DB",
            description="block dev database access",
            enabled=True,
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.10.8/32"),),
            protocol="tcp",
            destination_ports=frozenset({5432}),
            severity="critical",
            action="drop",
        )
        values.update(overrides)
        return Rule(**values)
    return rule


# Or plain helpers (preferred by AGENTS style — not necessarily fixtures):

def rule(**overrides) -> Rule: ...
def metadata(**overrides) -> PacketMetadata: ...
def app_config(tmp_path, rules) -> AppConfig: ...
```

Plain functions in `conftest.py` are importable by pytest as fixtures only if named fixtures; for helpers, put them in `tests/factories.py` and import — **prefer `tests/factories.py`** to avoid conftest import confusion:

- Create: `tests/factories.py` with `rule`, `metadata`, `app_config`
- Import from tests

- [ ] Commit: `test: centralize rule/metadata/app_config factories`

### Optional Task 4c: Metrics explicit counters

Replace `Metrics.update(**increments)` call sites with named methods:

```python
def incr_notifications_sent(self, n: int = 1) -> None: ...
def incr_notification_failures(self, n: int = 1) -> None: ...
def incr_notifications_suppressed(self, n: int = 1) -> None: ...
def incr_notification_queue_dropped(self, n: int = 1) -> None: ...
```

Delete generic `update` if unused. YAGNI if PR already large — skip.

### PR4 acceptance checklist

- [ ] `HealthServer(...)` without providers is a TypeError at call sites (no silent empty dashboard)
- [ ] `reload_rules` takes `tuple[Rule, ...]`, not full `AppConfig`
- [ ] One factory module; no four divergent `rule()` copies
- [ ] `make test` + `make lint` green

---

## Cross-PR regression matrix (run after each PR)

| Check | Command / method | Pass criteria |
|---|---|---|
| Unit + coverage | `make test` | exit 0 |
| Lint | `make lint` | exit 0 |
| Validate sample policy | `ibn-monitor validate --config config/policy.json` | exit 0, JSON `valid: true` |
| Synthetic match | `ibn-monitor check ... --destination-port 5432` | exit 2, matched true |
| Synthetic miss | same with port 443 | exit 0, matched false |
| nftables render | `ibn-monitor render-nftables --config config/policy.json` | drop rules present; alert-only absent |
| JSONL shape | PCAP or monitor unit test | keys: schema_version, event_id, event_type, observed_at, rule, network |
| API shape | health unit test | `/api/state` has metrics, rules, recent_events |
| Docs | manual | AGENTS/CONTEXT/README match module names |

---

## Out of scope (do not do in this plan)

- Changing dashboard UI/CSS or poll interval
- Live packet drop inside the sensor
- New webhook auth, retries, or backoff redesign
- Replacing stdlib HTTP server with a framework
- Async rewrite of capture path
- Prometheus metric renames

---

## Risk notes

| Risk | Mitigation |
|---|---|
| Wire format drift breaks log consumers | PR1 tests lock nested `rule`/`network` keys; keep `to_dict()` as single serializer |
| Webhook race/stop behavior regresses | Port stop Event + sentinel code verbatim; join timeout 5s |
| Schema-only validation worsens errors | Keep first schema error path; add CIDR/unique-ID messages in Python |
| Deleting `config/policy.schema.json` breaks external docs | Grep repo for path; update README/AGENTS in same PR |

---

## Execution handoff

Plan saved to `docs/superpowers/plans/2026-07-20-event-notifier-refactor.md`.

**Suggested ship order:** PR1 → PR2 → PR3 → PR4 (PR4 may merge into PR2 if the diff stays small).

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — same session, batch with checkpoints  

Which approach do you want?

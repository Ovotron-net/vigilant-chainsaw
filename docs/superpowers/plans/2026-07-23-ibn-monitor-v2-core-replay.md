# ibn-monitor V2 Core and Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the pure, cross-platform ibn-monitor v2 domain: explicit policy/config validation and migration, compiled matching, bounded metadata-only decoding, classic-PCAP replay, violation episodes, schema-v2 evidence envelopes, and v2 CLI validation/check/replay—without cutting live capture or nftables over from v1.

**Architecture:** Build v2 additively beside the working v1 runtime. Final v2 names (`Observation`, `PolicyRule`, `EvidenceEnvelope`) join `models.py`; new pure modules own policy compilation, decoding, PCAP streaming, episodes, migration, and replay. `config.py` keeps `load_config()` for the temporary v1 live/render path and adds `validate_v2_config()` / `load_v2_config()`. Phase 2 removes the transitional v1 path when AF_PACKET live capture lands.

**Tech Stack:** Python 3.11+, stdlib (`dataclasses`, `datetime`, `enum`, `hashlib`, `heapq`, `ipaddress`, `json`, `struct`, `uuid`), `jsonschema>=4.18,<5`, pytest, pytest-cov, Ruff. Scapy remains installed only because the untouched v1 live path still needs it; no Phase 1 v2 module imports Scapy.

## Global Constraints

- Execute in an isolated worktree created from commit `3b7e04796a0c845934dc6d806674adcfb499e365` or later. Do not carry the current uncommitted `src/ibn_monitor/enforcement.py` edit into the worktree.
- Python floor remains 3.11. Add no runtime dependency.
- Domain records are `@dataclass(frozen=True, slots=True)`. Mutable episode state stays private inside `episodes.py`.
- Raise `ConfigError` for v2 configuration failures; return typed diagnostics for validation warnings/errors.
- V2 rules are prohibited-flow assertions. Return every matching rule.
- Never copy or persist packet payload bytes. New decoder and PCAP interfaces expose header prefixes only.
- V2 replay supports classic PCAP only: Ethernet, raw IP, Linux cooked v1, and Linux cooked v2.
- Keep v1 `load_config()`, `PolicyEngine`, `PacketMetadata`, `Rule`, `Event`, `run --pcap`, live `run`, and `render-nftables` behavior unchanged in this phase.
- V2 `check` exit codes are 0 clear, 1 violation, 2 error. The temporary v1 `check` branch keeps its existing exit code until Phase 2 removes v1 CLI execution.
- Schema-v2 events are episode lifecycle envelopes; do not emit a parallel v2 per-packet violation stream.
- Run targeted tests after every red/green step. Run `pytest -q` and `ruff check .` before every commit.
- Commit only files named by the task. Preserve unrelated user changes.

---

## Transitional target shape

```text
v1 policy ── load_config ── existing live run / render-nftables (untouched)

v1 policy ── migrate-policy ── v2 policy
v2 policy ── validate_v2_config ── CompiledPolicy
                                         │
synthetic Observation ───────────────────┼── evaluate → all PolicyRule matches
                                         │
classic PCAP ── bounded decoder ─────────┴── EpisodeTracker
                                                │
                                                ▼
                                      schema-v2 EvidenceEnvelope JSONL
```

## File map

| Path | Phase 1 responsibility |
|---|---|
| `src/ibn_monitor/models.py` | Add frozen v2 policy, observation, diagnostic, episode-transition, and evidence-envelope types alongside v1 types. |
| `src/ibn_monitor/policy-v2.schema.json` | Packaged v2 structure/range schema. |
| `src/ibn_monitor/config.py` | Add v2 config records, diagnostics, canonical hashes, schema/semantic validation, and version detection. Preserve v1 loader. |
| `src/ibn_monitor/migration.py` | Pure v1 raw-JSON to v2 raw-JSON migration with explicit ambiguity diagnostics. |
| `src/ibn_monitor/policy.py` | Immutable compiled-policy IR, all-match evaluation, overlap diagnostics, and match explanations. |
| `src/ibn_monitor/decode.py` | Header accessor seam and bounded Ethernet/SLL/raw IPv4/IPv6 metadata decoder. |
| `src/ibn_monitor/pcap.py` | Header-only streaming classic-PCAP reader. |
| `src/ibn_monitor/episodes.py` | Deterministic bounded episode state machine. |
| `src/ibn_monitor/replay.py` | Event-time ordering, matching, episode transitions, evidence sequencing, JSONL output, and replay summary. |
| `src/ibn_monitor/cli.py` | Add v2-aware validate/check, `migrate-policy`, and `replay` while leaving live/render v1. |
| `src/ibn_monitor/events.py` | Add only the v2 evidence sequencer/serializer used by replay; v1 log/notifier code remains. |
| `pyproject.toml` | Package both policy schemas; no dependency change. |
| `tests/factories.py` | Add v2 policy/observation/config factories without changing v1 helpers. |
| `tests/packet_bytes.py` | Header-only packet builders for decoder/replay tests; no Scapy. |
| `tests/pcap_bytes.py` | Classic-PCAP byte builders; no Scapy. |
| `tests/test_*_v2.py` | Focused v2 model, config, policy, decode, PCAP, episode, replay, migration, and CLI tests. |
| `config/policy.v2.example.json` | Valid explicit v2 example used by tests/docs, without replacing v1 `config/policy.json`. |
| `README.md` / `CONTEXT.md` / `AGENTS.md` | Document the additive Phase 1 boundary and new domain names. |

---

### Task 1: Add the frozen v2 domain vocabulary

**Files:**
- Modify: `src/ibn_monitor/models.py:1-70`
- Modify: `tests/factories.py:1-70`
- Create: `tests/test_models_v2.py`

**Interfaces:**
- Consumes: existing `Network` and `Severity` aliases.
- Produces:

```python
FieldPresence
Diagnostic
PolicyMatch
PolicyRule
Observation
```

- [ ] **Step 1: Write failing immutability and wire-value tests**

```python
# tests/test_models_v2.py
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network

import pytest

from ibn_monitor.models import (
    DecodeOutcome,
    Diagnostic,
    FieldPresence,
    Observation,
    PolicyMatch,
    PolicyRule,
)


def test_v2_policy_and_observation_are_frozen():
    rule = PolicyRule(
        id="DEV-DB",
        description="development must not reach production database",
        enabled=True,
        match=PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.10.8/32"),),
            protocol="tcp",
            destination_ports=frozenset({5432}),
        ),
        severity="critical",
        enforcement="nftables_drop_candidate",
    )
    observation = Observation(
        captured_at=datetime(2026, 7, 23, tzinfo=UTC),
        monotonic_at=None,
        sensor_id="sensor-1",
        source_generation="replay-0",
        capture_point="pcap",
        interface=None,
        direction="unknown",
        wire_length=60,
        ip_version=4,
        source=ip_address("10.20.5.14"),
        destination=ip_address("10.50.10.8"),
        protocol="tcp",
        source_port=40000,
        destination_port=5432,
        tcp_flags=0x02,
        fields=FieldPresence.complete_tcp(),
        outcome="complete",
    )

    with pytest.raises(FrozenInstanceError):
        rule.enabled = False
    with pytest.raises(FrozenInstanceError):
        observation.destination_port = 443


def test_field_presence_and_diagnostic_values_are_stable():
    assert int(FieldPresence.complete_tcp()) == 127
    assert DecodeOutcome.__args__ == ("complete", "partial", "undecodable")
    diagnostic = Diagnostic("warning", "rule.overlap", "/rules/1", "overlaps R1")
    assert diagnostic.to_dict() == {
        "severity": "warning",
        "code": "rule.overlap",
        "path": "/rules/1",
        "message": "overlaps R1",
    }
```

- [ ] **Step 2: Run the test and verify the missing v2 types**

Run:

```bash
pytest tests/test_models_v2.py -q
```

Expected: collection ERROR naming `DecodeOutcome` or `Observation` as missing.

- [ ] **Step 3: Add the exact v2 public model surface**

Append these definitions after the existing v1 `Event`. Keep existing names unchanged.

```python
# models.py additions
from datetime import datetime
from enum import IntFlag
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

Address = IPv4Address | IPv6Address
PolicyProtocol = Literal["any", "tcp", "udp", "icmp"]
EnforcementDisposition = Literal["none", "nftables_drop_candidate"]
ObservedDirection = Literal["inbound", "outbound", "unknown"]
DecodeOutcome = Literal["complete", "partial", "undecodable"]
DiagnosticSeverity = Literal["error", "warning"]


class FieldPresence(IntFlag):
    IP_VERSION = 1 << 0
    SOURCE = 1 << 1
    DESTINATION = 1 << 2
    PROTOCOL = 1 << 3
    SOURCE_PORT = 1 << 4
    DESTINATION_PORT = 1 << 5
    TCP_FLAGS = 1 << 6
    ICMP = 1 << 7

    @classmethod
    def complete_tcp(cls) -> "FieldPresence":
        return (
            cls.IP_VERSION
            | cls.SOURCE
            | cls.DESTINATION
            | cls.PROTOCOL
            | cls.SOURCE_PORT
            | cls.DESTINATION_PORT
            | cls.TCP_FLAGS
        )


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: DiagnosticSeverity
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    source_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]
    protocol: PolicyProtocol
    destination_ports: frozenset[int] | None


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    description: str
    enabled: bool
    match: PolicyMatch
    severity: Severity
    enforcement: EnforcementDisposition


@dataclass(frozen=True, slots=True)
class Observation:
    captured_at: datetime
    monotonic_at: float | None
    sensor_id: str
    source_generation: str
    capture_point: str
    interface: str | None
    direction: ObservedDirection
    wire_length: int
    ip_version: int | None = None
    source: Address | None = None
    destination: Address | None = None
    protocol: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    fields: FieldPresence = FieldPresence(0)
    outcome: DecodeOutcome = "undecodable"
    decode_reason: str | None = None
    late: bool = False
```

Do not replace v1 `Protocol`, `Action`, `PacketMetadata`, `Rule`, or `Event` in this phase.

- [ ] **Step 4: Add reusable v2 factories**

```python
# tests/factories.py additions
from datetime import UTC, datetime
from ipaddress import ip_address

from ibn_monitor.models import FieldPresence, Observation, PolicyMatch, PolicyRule


def policy_rule(**overrides: Any) -> PolicyRule:
    values: dict[str, Any] = {
        "id": "DEV-DB",
        "description": "development must not reach production database",
        "enabled": True,
        "match": PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.10.8/32"),),
            protocol="tcp",
            destination_ports=frozenset({5432}),
        ),
        "severity": "critical",
        "enforcement": "nftables_drop_candidate",
    }
    values.update(overrides)
    return PolicyRule(**values)


def observation(**overrides: Any) -> Observation:
    values: dict[str, Any] = {
        "captured_at": datetime(2026, 7, 23, tzinfo=UTC),
        "monotonic_at": None,
        "sensor_id": "sensor-1",
        "source_generation": "replay-0",
        "capture_point": "pcap",
        "interface": None,
        "direction": "unknown",
        "wire_length": 60,
        "ip_version": 4,
        "source": ip_address("10.20.5.14"),
        "destination": ip_address("10.50.10.8"),
        "protocol": "tcp",
        "source_port": 40000,
        "destination_port": 5432,
        "tcp_flags": 0x02,
        "fields": FieldPresence.complete_tcp(),
        "outcome": "complete",
    }
    values.update(overrides)
    return Observation(**values)
```

- [ ] **Step 5: Run focused and full checks**

Run:

```bash
pytest tests/test_models_v2.py tests/test_events.py tests/test_engine.py -q
ruff check src/ibn_monitor/models.py tests/factories.py tests/test_models_v2.py
```

Expected: PASS; existing v1 model/event/engine tests remain unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/models.py tests/factories.py tests/test_models_v2.py
git commit -m "feat: add v2 policy and observation models"
```

---

### Task 2: Add schema-v2 configuration, diagnostics, and canonical revisions

**Files:**
- Create: `src/ibn_monitor/policy-v2.schema.json`
- Modify: `src/ibn_monitor/config.py:1-210`
- Modify: `pyproject.toml:24-31`
- Create: `tests/test_config_v2.py`
- Create: `config/policy.v2.example.json`

**Interfaces:**
- Consumes: `Diagnostic`, `PolicyMatch`, `PolicyRule`.
- Produces:

```python
detect_config_version(path: str | Path) -> int
validate_v2_config(path: str | Path) -> ConfigValidation
load_v2_config(path: str | Path, *, strict: bool = False) -> PolicyV2Config
canonical_policy_revision(rules: tuple[PolicyRule, ...]) -> str
canonical_config_revision(config: PolicyV2Config) -> str
```

- [ ] **Step 1: Write schema and semantic failure tests**

Create `tests/test_config_v2.py` with these tests:

```python
import json

import pytest

from ibn_monitor.config import ConfigError, detect_config_version, load_v2_config


def write_json(tmp_path, payload):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def valid_v2():
    return {
        "version": 2,
        "sensor": {
            "id": "edge-gw-01",
            "topology": "gateway",
            "capture_points": [
                {
                    "name": "wan",
                    "interface": "eth0",
                    "direction": "inbound",
                    "promiscuous": False,
                }
            ],
        },
        "rules": [
            {
                "id": "DEV-DB",
                "description": "development must not reach production database",
                "enabled": True,
                "match": {
                    "source_cidrs": ["10.20.0.0/16"],
                    "destination_cidrs": ["10.50.10.8/32"],
                    "protocol": "tcp",
                    "destination_ports": [5432],
                },
                "severity": "critical",
                "enforcement": "nftables_drop_candidate",
            }
        ],
    }


def test_detects_and_loads_v2_with_defaults(tmp_path):
    path = write_json(tmp_path, valid_v2())
    assert detect_config_version(path) == 2
    config = load_v2_config(path)
    assert config.sensor.id == "edge-gw-01"
    assert config.processing.observation_queue_capacity == 10_000
    assert config.episodes.idle_seconds == 30
    assert len(config.policy_revision) == 64
    assert len(config.config_revision) == 64


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p["sensor"].pop("id"), "sensor/id"),
        (lambda p: p["rules"][0]["match"].update(source_cidrs=[]), "source_cidrs"),
        (lambda p: p["rules"][0]["match"].pop("protocol"), "protocol"),
        (
            lambda p: p["rules"][0]["match"].update(
                protocol="icmp", destination_ports=[8]
            ),
            "destination_ports",
        ),
    ],
)
def test_rejects_implicit_or_invalid_v2_selectors(tmp_path, mutate, message):
    payload = valid_v2()
    mutate(payload)
    with pytest.raises(ConfigError, match=message):
        load_v2_config(write_json(tmp_path, payload))


def test_mirror_requires_promiscuous_capture(tmp_path):
    payload = valid_v2()
    payload["sensor"]["topology"] = "mirror"
    with pytest.raises(ConfigError, match="sensor.mirror_promiscuous"):
        load_v2_config(write_json(tmp_path, payload))


def test_revisions_ignore_json_order_but_include_description(tmp_path):
    first = valid_v2()
    second = json.loads(json.dumps(first, sort_keys=True))
    assert load_v2_config(write_json(tmp_path, first)).policy_revision == load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision

    second["rules"][0]["description"] = "changed description"
    assert load_v2_config(write_json(tmp_path, first)).policy_revision != load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision


def test_revision_normalizes_and_deduplicates_equivalent_cidrs(tmp_path):
    first = valid_v2()
    second = valid_v2()
    second["rules"][0]["match"]["source_cidrs"] = [
        "10.20.5.14/16",
        "10.20.0.0/16",
    ]
    assert load_v2_config(write_json(tmp_path, first)).policy_revision == load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision
```

- [ ] **Step 2: Run the tests and verify the v2 loader is missing**

Run:

```bash
pytest tests/test_config_v2.py -q
```

Expected: collection ERROR for `detect_config_version`.

- [ ] **Step 3: Add the complete packaged v2 schema**

Create `src/ibn_monitor/policy-v2.schema.json`. The schema must set `additionalProperties: false` at every object, require `version`, `sensor`, and `rules`, and encode these exact constraints:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.invalid/ibn-monitor/policy-v2.schema.json",
  "title": "ibn-monitor Policy v2",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "sensor", "rules"],
  "properties": {
    "version": {"const": 2},
    "sensor": {"$ref": "#/$defs/sensor"},
    "processing": {"$ref": "#/$defs/processing"},
    "episodes": {"$ref": "#/$defs/episodes"},
    "journal": {"$ref": "#/$defs/journal"},
    "http": {"$ref": "#/$defs/http"},
    "notifications": {"$ref": "#/$defs/notifications"},
    "rules": {
      "type": "array",
      "minItems": 1,
      "maxItems": 1000,
      "items": {"$ref": "#/$defs/rule"}
    }
  },
  "$defs": {
    "identifier": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]*$"
    },
    "sensor": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "topology", "capture_points"],
      "properties": {
        "id": {"$ref": "#/$defs/identifier"},
        "topology": {"enum": ["gateway", "mirror", "host"]},
        "capture_points": {
          "type": "array",
          "minItems": 1,
          "maxItems": 32,
          "items": {"$ref": "#/$defs/capture_point"}
        }
      }
    },
    "capture_point": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "interface"],
      "properties": {
        "name": {"$ref": "#/$defs/identifier"},
        "interface": {"type": "string", "minLength": 1, "maxLength": 64},
        "direction": {"enum": ["inbound", "outbound", "both"]},
        "promiscuous": {"type": "boolean"}
      }
    },
    "processing": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "observation_queue_capacity": {"type": "integer", "minimum": 1000, "maximum": 1000000},
        "queue_recovery_cooldown_seconds": {"type": "number", "minimum": 0, "maximum": 300},
        "graceful_drain_seconds": {"type": "number", "minimum": 1, "maximum": 60}
      }
    },
    "episodes": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "capacity": {"type": "integer", "minimum": 100, "maximum": 1000000},
        "idle_seconds": {"type": "number", "minimum": 1, "maximum": 3600},
        "progress_seconds": {"type": "number", "minimum": 1, "maximum": 3600},
        "replay_lateness_seconds": {"type": "number", "minimum": 0, "maximum": 60}
      }
    },
    "journal": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "file": {"type": "string", "minLength": 1},
        "max_bytes": {"type": "integer", "minimum": 1024},
        "backup_count": {"type": "integer", "minimum": 1},
        "fsync_interval_seconds": {"type": "number", "minimum": 0.1, "maximum": 60},
        "emergency_max_events": {"type": "integer", "minimum": 1, "maximum": 100000},
        "emergency_max_bytes": {"type": "integer", "minimum": 1024, "maximum": 1073741824}
      }
    },
    "listener": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": {"type": "boolean"},
        "bind": {"type": "string", "minLength": 1},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535}
      }
    },
    "http": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "probe": {"$ref": "#/$defs/listener"},
        "operations": {"$ref": "#/$defs/operations_listener"}
      }
    },
    "operations_listener": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": {"type": "boolean"},
        "bind": {"type": "string", "minLength": 1},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "allow_non_loopback": {"type": "boolean"}
      }
    },
    "notifications": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "webhook_url_env": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
        "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 60},
        "minimum_severity": {"enum": ["low", "medium", "high", "critical"]},
        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 20},
        "max_elapsed_seconds": {"type": "number", "minimum": 1, "maximum": 3600},
        "shutdown_drain_seconds": {"type": "number", "minimum": 0, "maximum": 60},
        "insecure_allow_http_loopback": {"type": "boolean"}
      }
    },
    "cidrs": {
      "type": "array",
      "minItems": 1,
      "maxItems": 256,
      "uniqueItems": true,
      "items": {"type": "string", "minLength": 1, "maxLength": 64}
    },
    "ports": {
      "oneOf": [
        {"const": "any"},
        {
          "type": "array",
          "minItems": 1,
          "maxItems": 1024,
          "uniqueItems": true,
          "items": {"type": "integer", "minimum": 1, "maximum": 65535}
        }
      ]
    },
    "match": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source_cidrs", "destination_cidrs", "protocol"],
      "properties": {
        "source_cidrs": {"$ref": "#/$defs/cidrs"},
        "destination_cidrs": {"$ref": "#/$defs/cidrs"},
        "protocol": {"enum": ["any", "tcp", "udp", "icmp"]},
        "destination_ports": {"$ref": "#/$defs/ports"}
      },
      "allOf": [
        {
          "if": {
            "properties": {"protocol": {"enum": ["tcp", "udp"]}},
            "required": ["protocol"]
          },
          "then": {"required": ["destination_ports"]},
          "else": {"not": {"required": ["destination_ports"]}}
        }
      ]
    },
    "rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "description", "enabled", "match", "severity", "enforcement"],
      "properties": {
        "id": {"$ref": "#/$defs/identifier"},
        "description": {
          "type": "string",
          "minLength": 1,
          "maxLength": 512,
          "pattern": "^[^\\u0000-\\u001F\\u007F]+$"
        },
        "enabled": {"type": "boolean"},
        "match": {"$ref": "#/$defs/match"},
        "severity": {"enum": ["low", "medium", "high", "critical"]},
        "enforcement": {"enum": ["none", "nftables_drop_candidate"]}
      }
    }
  }
}
```

Call `jsonschema.Draft202012Validator.check_schema` in the schema test so the checked-in schema itself is verified before instance validation.

- [ ] **Step 4: Package both schemas**

Change:

```toml
[tool.setuptools.package-data]
ibn_monitor = ["policy.schema.json", "policy-v2.schema.json"]
```

- [ ] **Step 5: Add frozen v2 config records and validation result**

Add to `config.py` without changing v1 dataclasses or `load_config()`:

```python
Topology = Literal["gateway", "mirror", "host"]
CaptureDirection = Literal["inbound", "outbound", "both"]


@dataclass(frozen=True, slots=True)
class CapturePointConfig:
    name: str
    interface: str
    direction: CaptureDirection
    promiscuous: bool


@dataclass(frozen=True, slots=True)
class SensorV2Config:
    id: str
    topology: Topology
    capture_points: tuple[CapturePointConfig, ...]


@dataclass(frozen=True, slots=True)
class ProcessingV2Config:
    observation_queue_capacity: int = 10_000
    queue_recovery_cooldown_seconds: float = 30.0
    graceful_drain_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class EpisodeV2Config:
    capacity: int = 10_000
    idle_seconds: float = 30.0
    progress_seconds: float = 60.0
    replay_lateness_seconds: float = 2.0


@dataclass(frozen=True, slots=True)
class JournalV2Config:
    file: str = "events-v2.jsonl"
    max_bytes: int = 10_485_760
    backup_count: int = 5
    fsync_interval_seconds: float = 1.0
    emergency_max_events: int = 1_000
    emergency_max_bytes: int = 8_388_608


@dataclass(frozen=True, slots=True)
class ListenerV2Config:
    enabled: bool
    bind: str
    port: int
    allow_non_loopback: bool = False


@dataclass(frozen=True, slots=True)
class HttpV2Config:
    probe: ListenerV2Config
    operations: ListenerV2Config


@dataclass(frozen=True, slots=True)
class NotificationV2Config:
    webhook_url_env: str | None = None
    timeout_seconds: float = 3.0
    minimum_severity: Severity = "high"
    max_attempts: int = 5
    max_elapsed_seconds: float = 60.0
    shutdown_drain_seconds: float = 5.0
    insecure_allow_http_loopback: bool = False


@dataclass(frozen=True, slots=True)
class PolicyV2Config:
    version: int
    sensor: SensorV2Config
    processing: ProcessingV2Config
    episodes: EpisodeV2Config
    journal: JournalV2Config
    http: HttpV2Config
    notifications: NotificationV2Config
    rules: tuple[PolicyRule, ...]
    policy_revision: str
    config_revision: str


@dataclass(frozen=True, slots=True)
class ConfigValidation:
    config: PolicyV2Config | None
    diagnostics: tuple[Diagnostic, ...]

    @property
    def valid(self) -> bool:
        return self.config is not None and not any(
            item.severity == "error" for item in self.diagnostics
        )
```

- [ ] **Step 6: Implement version detection, canonical wire dictionaries, and hashes**

```python
def detect_config_version(path: str | Path) -> int:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise ConfigError("root must be an object")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ConfigError("version must be an integer")
    return version


def _rule_wire(rule: PolicyRule) -> dict[str, object]:
    ports: str | list[int]
    if rule.match.destination_ports is None:
        ports = "any"
    else:
        ports = sorted(rule.match.destination_ports)
    match: dict[str, object] = {
        "source_cidrs": sorted({str(network) for network in rule.match.source_cidrs}),
        "destination_cidrs": sorted(
            {str(network) for network in rule.match.destination_cidrs}
        ),
        "protocol": rule.match.protocol,
    }
    if rule.match.protocol in {"tcp", "udp"}:
        match["destination_ports"] = ports
    return {
        "id": rule.id,
        "description": rule.description,
        "enabled": rule.enabled,
        "match": match,
        "severity": rule.severity,
        "enforcement": rule.enforcement,
    }


def _sha256(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_policy_revision(rules: tuple[PolicyRule, ...]) -> str:
    return _sha256([_rule_wire(rule) for rule in sorted(rules, key=lambda item: item.id)])


def _config_wire(config: PolicyV2Config) -> dict[str, object]:
    return {
        "version": config.version,
        "sensor": asdict(config.sensor),
        "processing": asdict(config.processing),
        "episodes": asdict(config.episodes),
        "journal": asdict(config.journal),
        "http": asdict(config.http),
        "notifications": asdict(config.notifications),
        "rules": [
            _rule_wire(rule) for rule in sorted(config.rules, key=lambda item: item.id)
        ],
    }


def canonical_config_revision(config: PolicyV2Config) -> str:
    return _sha256(_config_wire(config))
```

Import `asdict` from `dataclasses`. Because `NotificationV2Config` stores only the environment-variable name, this hashes every effective configuration value without resolving or hashing an environment value.

- [ ] **Step 7: Implement `validate_v2_config` and `load_v2_config`**

Use `resources.files("ibn_monitor").joinpath("policy-v2.schema.json")` and `Draft202012Validator`. Convert schema errors to:

```python
Diagnostic(
    severity="error",
    code="schema.invalid",
    path="/" + "/".join(str(part) for part in error.absolute_path),
    message=error.message,
)
```

Construct effective capture defaults with:

```python
_DIRECTION_DEFAULT = {"gateway": "inbound", "mirror": "inbound", "host": "both"}


def _capture_point(raw: dict[str, Any], topology: Topology) -> CapturePointConfig:
    return CapturePointConfig(
        name=raw["name"],
        interface=raw["interface"],
        direction=cast(CaptureDirection, raw.get("direction", _DIRECTION_DEFAULT[topology])),
        promiscuous=bool(raw.get("promiscuous", topology == "mirror")),
    )
```

Use these effective HTTP defaults when the corresponding objects or fields are omitted:

```python
probe = ListenerV2Config(
    enabled=bool(probe_raw.get("enabled", True)),
    bind=str(probe_raw.get("bind", "127.0.0.1")),
    port=int(probe_raw.get("port", 9108)),
)
operations = ListenerV2Config(
    enabled=bool(operations_raw.get("enabled", True)),
    bind=str(operations_raw.get("bind", "127.0.0.1")),
    port=int(operations_raw.get("port", 9109)),
    allow_non_loopback=bool(operations_raw.get("allow_non_loopback", False)),
)
```

Add semantic error `http.operations_non_loopback_unacknowledged` when the operations bind is not a loopback IP literal and `allow_non_loopback` is false. Hostnames are rejected for this Phase 1 acknowledgement check so `localhost` cannot resolve differently at runtime.

Semantic validation must append stable diagnostics for:

```text
sensor.duplicate_capture_point
sensor.duplicate_interface
sensor.mirror_promiscuous
http.operations_non_loopback_unacknowledged
rule.duplicate_id
rule.invalid_cidr
rule.impossible_ip_family
rule.overlap
```

For this task, implement every error except `rule.overlap`; Task 4 adds that warning through `policy.find_overlaps`. Normalize CIDRs with `ip_network(value, strict=False)`, deduplicate equivalent normalized networks, and sort them by `(version, network_address, prefixlen)`. Represent destination ports as `None` for literal `"any"` and as `frozenset[int]` otherwise.

After all schema and semantic checks succeed, construct the effective config in two passes so there is no revision cycle:

```python
provisional = PolicyV2Config(
    version=2,
    sensor=sensor,
    processing=processing,
    episodes=episodes,
    journal=journal,
    http=http,
    notifications=notifications,
    rules=rules,
    policy_revision=canonical_policy_revision(rules),
    config_revision="",
)
config = replace(
    provisional,
    config_revision=canonical_config_revision(provisional),
)
```

`load_v2_config(path, strict=False)` calls `validate_v2_config` and raises `ConfigError` with newline-joined `code path: message` entries when errors exist or when `strict=True` and warnings exist.

- [ ] **Step 8: Add the canonical example**

Create `config/policy.v2.example.json` using the exact v2 policy from `valid_v2()` plus explicit `processing` and `episodes` defaults. Keep `config/policy.json` unchanged for v1 live tests.

- [ ] **Step 9: Run focused and full validation tests**

Run:

```bash
pytest tests/test_config_v2.py tests/test_config.py -q
ruff check src/ibn_monitor/config.py tests/test_config_v2.py
pytest -q
```

Expected: PASS; v1 config tests remain green.

- [ ] **Step 10: Commit**

```bash
git add src/ibn_monitor/policy-v2.schema.json src/ibn_monitor/config.py pyproject.toml tests/test_config_v2.py config/policy.v2.example.json
git commit -m "feat: add explicit v2 policy configuration"
```

---

### Task 3: Add explicit v1-to-v2 policy migration

**Files:**
- Create: `src/ibn_monitor/migration.py`
- Create: `tests/test_migration.py`

**Interfaces:**
- Consumes: raw parsed v1 JSON and explicit sensor/topology/capture-point choices.
- Produces:

```python
MigrationRequest
MigrationResult
migrate_v1_policy(raw: object, request: MigrationRequest) -> MigrationResult
```

- [ ] **Step 1: Write migration success and ambiguity tests**

```python
# tests/test_migration.py
from ibn_monitor.migration import MigrationRequest, migrate_v1_policy


def request():
    return MigrationRequest(
        sensor_id="edge-gw-01",
        topology="gateway",
        capture_point_name="wan",
        interface="eth0",
    )


def test_migrates_explicit_v1_rule_without_changing_input():
    raw = {
        "version": 1,
        "rules": [
            {
                "id": "R1",
                "description": "test",
                "enabled": True,
                "source_cidrs": ["10.0.0.0/8"],
                "destination_cidrs": ["192.0.2.1/32"],
                "protocol": "tcp",
                "destination_ports": [443],
                "severity": "high",
                "action": "drop",
            }
        ],
    }
    result = migrate_v1_policy(raw, request())
    assert result.valid
    assert raw["version"] == 1
    assert result.payload["version"] == 2
    assert result.payload["rules"][0]["enforcement"] == "nftables_drop_candidate"
    assert result.payload["sensor"]["capture_points"][0]["direction"] == "inbound"


def test_refuses_ambiguous_missing_cidrs_and_ports():
    raw = {"version": 1, "rules": [{"id": "R1", "protocol": "tcp"}]}
    result = migrate_v1_policy(raw, request())
    assert result.payload is None
    assert [item.code for item in result.diagnostics] == [
        "migration.ambiguous_source_cidrs",
        "migration.ambiguous_destination_cidrs",
        "migration.ambiguous_destination_ports",
    ]


def test_mirror_migration_forces_promiscuous_default():
    req = MigrationRequest("mirror-1", "mirror", "span", "eth1")
    raw = {
        "version": 1,
        "rules": [
            {
                "id": "R1",
                "source_cidrs": ["0.0.0.0/0"],
                "destination_cidrs": ["0.0.0.0/0"],
                "protocol": "icmp",
            }
        ],
    }
    point = migrate_v1_policy(raw, req).payload["sensor"]["capture_points"][0]
    assert point["promiscuous"] is True
```

Add a fourth test with `sensor.bpf_filter = "tcp port 443"` and assert the result has no payload and the single diagnostic code is `migration.unsupported_bpf_filter`.

- [ ] **Step 2: Run the tests and verify the module is missing**

Run:

```bash
pytest tests/test_migration.py -q
```

Expected: collection ERROR for `ibn_monitor.migration`.

- [ ] **Step 3: Implement frozen request/result records**

```python
@dataclass(frozen=True, slots=True)
class MigrationRequest:
    sensor_id: str
    topology: Topology
    capture_point_name: str
    interface: str


@dataclass(frozen=True, slots=True)
class MigrationResult:
    payload: dict[str, object] | None
    diagnostics: tuple[Diagnostic, ...]

    @property
    def valid(self) -> bool:
        return self.payload is not None and not any(
            item.severity == "error" for item in self.diagnostics
        )
```

- [ ] **Step 4: Implement deterministic migration**

`migrate_v1_policy` must deep-copy through JSON-compatible construction, never mutate `raw`, and:

```python
def _migrate_rule(
    rule: dict[str, Any],
    index: int,
) -> tuple[dict[str, object] | None, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    for field in ("source_cidrs", "destination_cidrs"):
        if not rule.get(field):
            diagnostics.append(
                Diagnostic(
                    "error",
                    f"migration.ambiguous_{field}",
                    f"/rules/{index}/{field}",
                    f"v1 omitted/empty {field} meant any; write explicit /0 networks",
                )
            )
    protocol = str(rule.get("protocol", "any")).lower()
    if protocol in {"tcp", "udp"} and not rule.get("destination_ports"):
        diagnostics.append(
            Diagnostic(
                "error",
                "migration.ambiguous_destination_ports",
                f"/rules/{index}/destination_ports",
                "v1 omitted/empty ports meant any; choose \"any\" or explicit ports",
            )
        )
    if diagnostics:
        return None, diagnostics

    match: dict[str, object] = {
        "source_cidrs": list(rule["source_cidrs"]),
        "destination_cidrs": list(rule["destination_cidrs"]),
        "protocol": protocol,
    }
    if protocol in {"tcp", "udp"}:
        match["destination_ports"] = list(rule["destination_ports"])
    migrated = {
        "id": rule["id"],
        "description": rule.get("description", rule["id"]),
        "enabled": rule.get("enabled", True),
        "match": match,
        "severity": str(rule.get("severity", "high")).lower(),
        "enforcement": (
            "nftables_drop_candidate"
            if str(rule.get("action", "alert")).lower() == "drop"
            else "none"
        ),
    }
    return migrated, diagnostics
```

The top-level function applies this exact mapping:

- Emit `sensor` from `MigrationRequest`; use direction `inbound` for gateway/mirror and `both` for host, and set promiscuous true only for mirror unless the v1 sensor explicitly requested true.
- Reject a v1 `sensor.bpf_filter` other than the old default `"ip or ip6"` with `migration.unsupported_bpf_filter`; v2 does not accept free-form BPF.
- Copy v1 `logging.file`, `max_bytes`, and `backup_count` to the same keys under `journal`; omit absent values so v2 defaults apply.
- Copy v1 `health.enabled`, `bind`, and `port` to `http.probe`. Set `http.operations.enabled` to the same explicit v1 enabled value when present, but omit its bind/port so the safe loopback/9109 v2 defaults apply.
- Copy v1 notification `webhook_url_env`, `timeout_seconds`, and `minimum_severity`; omit `deduplication_seconds`, because episode aggregation replaces notification deduplication.
- Preserve the input rule order in output and diagnostics; the loader later canonicalizes revision ordering.
- Return no payload if any error diagnostic exists. Otherwise return a fresh JSON-compatible dictionary containing only lists, dictionaries, strings, numbers, booleans, and nulls.

Diagnostics are ordered first by top-level migration checks, then by rule index and field order.

- [ ] **Step 5: Validate migrated output in the test**

Extend the success test:

```python
import json
from ibn_monitor.config import load_v2_config

path = tmp_path / "migrated.json"
path.write_text(json.dumps(result.payload), encoding="utf-8")
assert load_v2_config(path).rules[0].id == "R1"
```

Run:

```bash
pytest tests/test_migration.py tests/test_config_v2.py -q
ruff check src/ibn_monitor/migration.py tests/test_migration.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/migration.py tests/test_migration.py
git commit -m "feat: add explicit v1 policy migration"
```

---

### Task 4: Compile v2 policies and evaluate all matching assertions

**Files:**
- Create: `src/ibn_monitor/policy.py`
- Create: `tests/test_policy_v2.py`
- Modify: `src/ibn_monitor/config.py`
- Modify: `tests/test_config_v2.py`

**Interfaces:**
- Consumes: `PolicyRule`, `Observation`, policy revision.
- Produces:

```python
compile_policy(rules: tuple[PolicyRule, ...], revision: str) -> CompiledPolicy
evaluate_policy(policy: CompiledPolicy, observation: Observation) -> tuple[PolicyMatchResult, ...]
find_overlaps(rules: tuple[PolicyRule, ...]) -> tuple[tuple[str, str], ...]
```

- [ ] **Step 1: Write all-match, partial-field, and overlap tests**

```python
# tests/test_policy_v2.py
from dataclasses import replace
from ipaddress import ip_network

from factories import observation, policy_rule
from ibn_monitor.models import FieldPresence, PolicyMatch
from ibn_monitor.policy import compile_policy, evaluate_policy, find_overlaps


def test_reports_every_matching_rule():
    rules = (policy_rule(id="R1"), policy_rule(id="R2", enforcement="none"))
    matches = evaluate_policy(compile_policy(rules, "a" * 64), observation())
    assert [match.rule.id for match in matches] == ["R1", "R2"]


def test_partial_observation_matches_only_when_constrained_fields_are_known():
    cidr_only = policy_rule(
        id="CIDR",
        match=PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.0.0/16"),),
            protocol="any",
            destination_ports=None,
        ),
    )
    partial = replace(
        observation(),
        protocol=None,
        source_port=None,
        destination_port=None,
        fields=(
            FieldPresence.IP_VERSION
            | FieldPresence.SOURCE
            | FieldPresence.DESTINATION
        ),
        outcome="partial",
        decode_reason="ipv6_extension_limit",
    )
    assert [item.rule.id for item in evaluate_policy(
        compile_policy((cidr_only, policy_rule()), "b" * 64), partial
    )] == ["CIDR"]


def test_overlap_detection_is_stable_and_ignores_disabled_rules():
    rules = (
        policy_rule(id="BROAD"),
        policy_rule(id="NARROW"),
        policy_rule(id="OFF", enabled=False),
    )
    assert find_overlaps(rules) == (("BROAD", "NARROW"),)
```

- [ ] **Step 2: Run the tests and verify the module is missing**

Run:

```bash
pytest tests/test_policy_v2.py -q
```

Expected: collection ERROR for `ibn_monitor.policy`.

- [ ] **Step 3: Implement immutable compiled predicates**

```python
@dataclass(frozen=True, slots=True)
class CompiledPredicate:
    rule: PolicyRule
    ip_version: int
    source_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    revision: str
    predicates: tuple[CompiledPredicate, ...]


@dataclass(frozen=True, slots=True)
class PolicyMatchResult:
    rule: PolicyRule
    predicate: CompiledPredicate


def compile_policy(rules: tuple[PolicyRule, ...], revision: str) -> CompiledPolicy:
    predicates: list[CompiledPredicate] = []
    for rule in sorted(rules, key=lambda item: item.id):
        if not rule.enabled:
            continue
        source_versions = {network.version for network in rule.match.source_cidrs}
        destination_versions = {
            network.version for network in rule.match.destination_cidrs
        }
        for version in sorted(source_versions & destination_versions):
            predicates.append(
                CompiledPredicate(
                    rule=rule,
                    ip_version=version,
                    source_cidrs=tuple(
                        network
                        for network in rule.match.source_cidrs
                        if network.version == version
                    ),
                    destination_cidrs=tuple(
                        network
                        for network in rule.match.destination_cidrs
                        if network.version == version
                    ),
                )
            )
    return CompiledPolicy(revision=revision, predicates=tuple(predicates))
```

- [ ] **Step 4: Implement known-field matching**

Use a private `_required_fields(rule)` helper:

```python
def _required_fields(rule: PolicyRule) -> FieldPresence:
    required = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
    )
    if rule.match.protocol != "any":
        required |= FieldPresence.PROTOCOL
    if rule.match.destination_ports is not None:
        required |= FieldPresence.DESTINATION_PORT
    return required


def evaluate_policy(
    policy: CompiledPolicy, observation: Observation
) -> tuple[PolicyMatchResult, ...]:
    if observation.source is None or observation.destination is None:
        return ()
    matches: list[PolicyMatchResult] = []
    for predicate in policy.predicates:
        rule = predicate.rule
        if observation.ip_version != predicate.ip_version:
            continue
        required = _required_fields(rule)
        if observation.fields & required != required:
            continue
        if not any(observation.source in network for network in predicate.source_cidrs):
            continue
        if not any(
            observation.destination in network
            for network in predicate.destination_cidrs
        ):
            continue
        if rule.match.protocol != "any" and observation.protocol != rule.match.protocol:
            continue
        ports = rule.match.destination_ports
        if ports is not None and observation.destination_port not in ports:
            continue
        matches.append(PolicyMatchResult(rule=rule, predicate=predicate))
    return tuple(matches)
```

- [ ] **Step 5: Implement deterministic overlap diagnostics**

Two enabled rules overlap when at least one same-family source network overlaps, at least one same-family destination network overlaps, their protocols are equal or either is `any`, and their port domains intersect. Treat `None` as all ports. Return sorted ID pairs once.

After `find_overlaps` passes, call it from `validate_v2_config` and append:

```python
Diagnostic(
    "warning",
    "rule.overlap",
    f"/rules/{right_index}",
    f"rule {right_id} overlaps {left_id}; every match will be reported",
)
```

Add a strict-mode test proving `load_v2_config(path, strict=True)` raises while non-strict load succeeds with the warning.

- [ ] **Step 6: Run focused and full checks**

Run:

```bash
pytest tests/test_policy_v2.py tests/test_config_v2.py -q
ruff check src/ibn_monitor/policy.py src/ibn_monitor/config.py tests/test_policy_v2.py
pytest -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ibn_monitor/policy.py src/ibn_monitor/config.py tests/test_policy_v2.py tests/test_config_v2.py
git commit -m "feat: compile and evaluate v2 policies"
```

---

### Task 5: Add the header-access seam and IPv4 metadata decoder

**Files:**
- Create: `src/ibn_monitor/decode.py`
- Create: `tests/packet_bytes.py`
- Create: `tests/test_decode_v2.py`

**Interfaces:**
- Consumes: bounded header prefixes supplied by `HeaderReader`.
- Produces:

```python
HeaderReader
ObservationContext
decode_observation(reader: HeaderReader, datalink: int, context: ObservationContext) -> Observation
```

- [ ] **Step 1: Add non-Scapy Ethernet/IPv4 packet builders**

```python
# tests/packet_bytes.py
import ipaddress
import struct

ETHERNET = 1
RAW = 101
LINUX_SLL = 113
LINUX_SLL2 = 276


def tcp_header(source_port=40000, destination_port=5432, flags=0x02):
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )


def udp_header(source_port=40000, destination_port=53):
    return struct.pack("!HHHH", source_port, destination_port, 8, 0)


def ipv4_packet(payload, protocol, source="10.20.5.14", destination="10.50.10.8", fragment=0):
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        fragment,
        64,
        protocol,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return header + payload


def ethernet_frame(payload, ethertype=0x0800, vlan_types=()):
    frame = b"\x00" * 12
    for vlan_type in vlan_types:
        frame += struct.pack("!HH", vlan_type, 1)
    return frame + struct.pack("!H", ethertype) + payload
```

- [ ] **Step 2: Write IPv4, VLAN, fragment, and no-payload-access tests**

```python
# tests/test_decode_v2.py
from datetime import UTC, datetime

from packet_bytes import ETHERNET, ethernet_frame, ipv4_packet, tcp_header, udp_header
from ibn_monitor.decode import ObservationContext, decode_observation


class TrackingReader:
    def __init__(self, data, wire_length=None):
        self.data = data
        self.wire_length = wire_length or len(data)
        self.requests = []

    def prefix(self, length):
        self.requests.append(length)
        return self.data[:length]


def context():
    return ObservationContext(
        captured_at=datetime(2026, 7, 23, tzinfo=UTC),
        monotonic_at=None,
        sensor_id="sensor-1",
        source_generation="replay-0",
        capture_point="pcap",
        interface=None,
        direction="unknown",
    )


def test_decodes_ethernet_ipv4_tcp_without_requesting_payload():
    headers = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    reader = TrackingReader(headers + b"secret payload", wire_length=1500)
    result = decode_observation(reader, ETHERNET, context())
    assert result.protocol == "tcp"
    assert result.destination_port == 5432
    assert result.wire_length == 1500
    assert max(reader.requests) == len(headers)


def test_decodes_two_vlan_tags_and_udp():
    headers = ethernet_frame(
        ipv4_packet(udp_header(), protocol=17),
        ethertype=0x0800,
        vlan_types=(0x88A8, 0x8100),
    )
    result = decode_observation(TrackingReader(headers), ETHERNET, context())
    assert result.protocol == "udp"
    assert result.destination_port == 53


def test_non_initial_fragment_is_partial_but_keeps_endpoints():
    frame = ethernet_frame(ipv4_packet(b"", protocol=6, fragment=1))
    result = decode_observation(TrackingReader(frame), ETHERNET, context())
    assert result.outcome == "partial"
    assert result.decode_reason == "non_initial_fragment"
    assert result.source is not None
    assert result.destination_port is None
```

- [ ] **Step 3: Run the tests and verify the decoder is missing**

Run:

```bash
pytest tests/test_decode_v2.py -q
```

Expected: collection ERROR for `ibn_monitor.decode`.

- [ ] **Step 4: Implement the accessor contract and link parsing**

```python
# decode.py
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Protocol

from .models import FieldPresence, Observation, ObservedDirection

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
MAX_HEADER_BYTES = 512
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}


class HeaderReader(Protocol):
    wire_length: int

    def prefix(self, length: int) -> bytes:
        """Return at most length bytes from the record start."""


@dataclass(frozen=True, slots=True)
class ObservationContext:
    captured_at: datetime
    monotonic_at: float | None
    sensor_id: str
    source_generation: str
    capture_point: str
    interface: str | None
    direction: ObservedDirection


class _DecodeFailure(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _need(reader: HeaderReader, length: int) -> bytes:
    if length > MAX_HEADER_BYTES:
        raise _DecodeFailure("header_byte_limit")
    data = reader.prefix(length)
    if len(data) < length:
        raise _DecodeFailure("truncated_header")
    return data


def _need_within(
    reader: HeaderReader,
    length: int,
    packet_end: int,
) -> bytes:
    if length > packet_end:
        raise _DecodeFailure("header_exceeds_ip_length")
    return _need(reader, length)


def _link(reader: HeaderReader, datalink: int) -> tuple[int, int]:
    if datalink == DLT_RAW:
        version = _need(reader, 1)[0] >> 4
        return 0, 0x0800 if version == 4 else 0x86DD
    if datalink == DLT_LINUX_SLL:
        data = _need(reader, 16)
        return 16, int.from_bytes(data[14:16], "big")
    if datalink == DLT_LINUX_SLL2:
        data = _need(reader, 20)
        return 20, int.from_bytes(data[0:2], "big")
    if datalink != DLT_EN10MB:
        raise _DecodeFailure("unsupported_datalink")
    data = _need(reader, 14)
    offset = 14
    ethertype = int.from_bytes(data[12:14], "big")
    vlan_depth = 0
    while ethertype in _VLAN_TYPES:
        vlan_depth += 1
        if vlan_depth > 2:
            raise _DecodeFailure("vlan_depth_limit")
        data = _need(reader, offset + 4)
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    return offset, ethertype
```

- [ ] **Step 5: Implement IPv4 and transport decoding**

`decode_observation` first creates an undecodable base `Observation` from `ObservationContext` and `reader.wire_length`. It calls `_link` and dispatches only EtherTypes `0x0800` and `0x86DD`. Task 6 adds IPv6; for now IPv6 returns reason `ipv6_not_implemented`.

Implement IPv4 with:

```python
def _decode_ipv4(
    reader: HeaderReader, offset: int, base: Observation
) -> Observation:
    data = _need(reader, offset + 20)
    version_ihl = data[offset]
    if version_ihl >> 4 != 4:
        raise _DecodeFailure("invalid_ipv4_version")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        raise _DecodeFailure("invalid_ipv4_ihl")
    data = _need(reader, offset + ihl)
    total_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
    if total_length < ihl:
        raise _DecodeFailure("invalid_ipv4_total_length")
    packet_end = offset + total_length
    source = ip_address(data[offset + 12 : offset + 16])
    destination = ip_address(data[offset + 16 : offset + 20])
    protocol_number = data[offset + 9]
    fragment = int.from_bytes(data[offset + 6 : offset + 8], "big")
    fields = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
        | FieldPresence.PROTOCOL
    )
    protocol = {1: "icmp", 6: "tcp", 17: "udp"}.get(
        protocol_number, f"ip:{protocol_number}"
    )
    partial = replace(
        base,
        ip_version=4,
        source=source,
        destination=destination,
        protocol=protocol,
        fields=fields,
        outcome="complete",
    )
    if fragment & 0x1FFF:
        return replace(
            partial,
            outcome="partial",
            decode_reason="non_initial_fragment",
        )
    try:
        return _decode_transport(
            reader,
            offset + ihl,
            packet_end,
            protocol,
            partial,
        )
    except _DecodeFailure as error:
        return replace(
            partial,
            outcome="partial",
            decode_reason=error.reason,
        )
```

Add the exact transport and public-dispatch implementation:

```python
def _decode_transport(
    reader: HeaderReader,
    offset: int,
    packet_end: int,
    protocol: str,
    observation: Observation,
) -> Observation:
    if protocol == "tcp":
        data = _need_within(reader, offset + 20, packet_end)
        header_length = (data[offset + 12] >> 4) * 4
        if not 20 <= header_length <= 60:
            raise _DecodeFailure("invalid_tcp_data_offset")
        data = _need_within(reader, offset + header_length, packet_end)
        return replace(
            observation,
            source_port=int.from_bytes(data[offset : offset + 2], "big"),
            destination_port=int.from_bytes(data[offset + 2 : offset + 4], "big"),
            tcp_flags=data[offset + 13],
            fields=(
                observation.fields
                | FieldPresence.SOURCE_PORT
                | FieldPresence.DESTINATION_PORT
                | FieldPresence.TCP_FLAGS
            ),
        )
    if protocol == "udp":
        data = _need_within(reader, offset + 8, packet_end)
        return replace(
            observation,
            source_port=int.from_bytes(data[offset : offset + 2], "big"),
            destination_port=int.from_bytes(data[offset + 2 : offset + 4], "big"),
            fields=(
                observation.fields
                | FieldPresence.SOURCE_PORT
                | FieldPresence.DESTINATION_PORT
            ),
        )
    if protocol == "icmp":
        data = _need_within(reader, offset + 2, packet_end)
        return replace(
            observation,
            icmp_type=data[offset],
            icmp_code=data[offset + 1],
            fields=observation.fields | FieldPresence.ICMP,
        )
    return observation


def decode_observation(
    reader: HeaderReader,
    datalink: int,
    context: ObservationContext,
) -> Observation:
    base = Observation(
        captured_at=context.captured_at,
        monotonic_at=context.monotonic_at,
        sensor_id=context.sensor_id,
        source_generation=context.source_generation,
        capture_point=context.capture_point,
        interface=context.interface,
        direction=context.direction,
        wire_length=reader.wire_length,
    )
    try:
        offset, ethertype = _link(reader, datalink)
        if ethertype == 0x0800:
            return _decode_ipv4(reader, offset, base)
        if ethertype == 0x86DD:
            return replace(base, decode_reason="ipv6_not_implemented")
        return replace(base, decode_reason=f"unsupported_ethertype:{ethertype:#06x}")
    except _DecodeFailure as error:
        return replace(base, decode_reason=error.reason)
```

The `try/except` in `_decode_ipv4` preserves known L3 fields while link/L3 failures remain undecodable. Add a regression with an IPv4 total length too short for its TCP header and assert `partial` / `header_exceeds_ip_length`; padding or bytes after the IP packet must never satisfy a transport-header read.

- [ ] **Step 6: Run focused checks**

Run:

```bash
pytest tests/test_decode_v2.py -q
ruff check src/ibn_monitor/decode.py tests/packet_bytes.py tests/test_decode_v2.py
```

Expected: all IPv4 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ibn_monitor/decode.py tests/packet_bytes.py tests/test_decode_v2.py
git commit -m "feat: decode bounded IPv4 header metadata"
```

---

### Task 6: Extend the decoder for IPv6, extension headers, and partial outcomes

**Files:**
- Modify: `src/ibn_monitor/decode.py`
- Modify: `tests/packet_bytes.py`
- Modify: `tests/test_decode_v2.py`

**Interfaces:**
- Extends `decode_observation` without changing its signature.
- Produces complete/partial IPv6 `Observation` values with ICMPv6 normalized to protocol `"icmp"`.

- [ ] **Step 1: Add IPv6 byte builders**

```python
# tests/packet_bytes.py additions
def ipv6_packet(
    payload,
    next_header,
    source="2001:db8::1",
    destination="2001:db8::2",
):
    version_flow = 6 << 28
    header = struct.pack(
        "!IHBB16s16s",
        version_flow,
        len(payload),
        next_header,
        64,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return header + payload


def ipv6_options(next_header, payload=b""):
    padded = payload + b"\x00" * ((6 - len(payload)) % 8)
    return bytes([next_header, len(padded) // 8]) + padded


def ipv6_fragment(next_header, offset=0, more=False):
    offset_flags = (offset << 3) | int(more)
    return struct.pack("!BBHI", next_header, 0, offset_flags, 1)


def icmp_header(type_=128, code=0):
    return bytes([type_, code]) + b"\x00" * 6
```

- [ ] **Step 2: Write IPv6 extension, fragment, and bound tests**

```python
from packet_bytes import icmp_header, ipv6_fragment, ipv6_options, ipv6_packet


def test_decodes_icmpv6_after_hop_by_hop_header():
    packet = ipv6_packet(
        ipv6_options(58) + icmp_header(),
        next_header=0,
    )
    result = decode_observation(TrackingReader(packet), 101, context())
    assert result.ip_version == 6
    assert result.protocol == "icmp"
    assert result.icmp_type == 128
    assert result.icmp_code == 0


def test_non_initial_ipv6_fragment_is_partial():
    packet = ipv6_packet(
        ipv6_fragment(17, offset=1) + b"\x00" * 8,
        next_header=44,
    )
    result = decode_observation(TrackingReader(packet), 101, context())
    assert result.outcome == "partial"
    assert result.decode_reason == "non_initial_fragment"
    assert result.destination_port is None


def test_ipv6_extension_count_is_bounded():
    payload = udp_header()
    next_header = 17
    for _ in range(9):
        payload = ipv6_options(next_header) + payload
        next_header = 0
    result = decode_observation(
        TrackingReader(ipv6_packet(payload, next_header=0)),
        101,
        context(),
    )
    assert result.outcome == "partial"
    assert result.decode_reason == "ipv6_extension_count_limit"
```

- [ ] **Step 3: Run the new tests and verify IPv6 is not implemented**

Run:

```bash
pytest tests/test_decode_v2.py -q
```

Expected: the IPv6 tests FAIL with `ipv6_not_implemented`.

- [ ] **Step 4: Implement the bounded IPv6 walker**

Add these constants:

```python
_IPV6_OPTION_HEADERS = {0, 43, 60, 135}
_IPV6_FRAGMENT = 44
_IPV6_AH = 51
_IPV6_ESP = 50
_IPV6_NO_NEXT = 59
MAX_IPV6_EXTENSIONS = 8
```

Implement:

```python
def _decode_ipv6(
    reader: HeaderReader, offset: int, base: Observation
) -> Observation:
    data = _need(reader, offset + 40)
    if data[offset] >> 4 != 6:
        raise _DecodeFailure("invalid_ipv6_version")
    source = ip_address(data[offset + 8 : offset + 24])
    destination = ip_address(data[offset + 24 : offset + 40])
    payload_length = int.from_bytes(data[offset + 4 : offset + 6], "big")
    next_header = data[offset + 6]
    cursor = offset + 40
    packet_end = cursor + payload_length
    fields = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
    )
    partial = replace(
        base,
        ip_version=6,
        source=source,
        destination=destination,
        fields=fields,
        outcome="partial",
    )
    if payload_length == 0 and next_header != _IPV6_NO_NEXT:
        return replace(partial, decode_reason="ipv6_jumbogram_unsupported")

    extension_count = 0
    while next_header in _IPV6_OPTION_HEADERS | {
        _IPV6_FRAGMENT,
        _IPV6_AH,
        _IPV6_ESP,
    }:
        extension_count += 1
        if extension_count > MAX_IPV6_EXTENSIONS:
            return replace(
                partial,
                decode_reason="ipv6_extension_count_limit",
            )
        if next_header == _IPV6_ESP:
            return replace(partial, decode_reason="encrypted_esp")
        data = _need_within(reader, cursor + 2, packet_end)
        following = data[cursor]
        if next_header == _IPV6_FRAGMENT:
            data = _need_within(reader, cursor + 8, packet_end)
            fragment = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
            if fragment >> 3:
                return replace(
                    partial,
                    protocol={6: "tcp", 17: "udp", 58: "icmp"}.get(
                        following, f"ip:{following}"
                    ),
                    fields=fields | FieldPresence.PROTOCOL,
                    decode_reason="non_initial_fragment",
                )
            header_length = 8
        elif next_header == _IPV6_AH:
            header_length = (data[cursor + 1] + 2) * 4
        else:
            header_length = (data[cursor + 1] + 1) * 8
        _need_within(reader, cursor + header_length, packet_end)
        cursor += header_length
        next_header = following

    protocol = {6: "tcp", 17: "udp", 58: "icmp"}.get(
        next_header, f"ip:{next_header}"
    )
    complete = replace(
        partial,
        protocol=protocol,
        fields=fields | FieldPresence.PROTOCOL,
        outcome="complete",
        decode_reason=None,
    )
    if next_header == _IPV6_NO_NEXT:
        return complete
    try:
        return _decode_transport(
            reader,
            cursor,
            packet_end,
            protocol,
            complete,
        )
    except _DecodeFailure as error:
        return replace(
            complete,
            outcome="partial",
            decode_reason=error.reason,
        )
```

Dispatch EtherType `0x86DD` to `_decode_ipv6`.

When `_need_within` fails while walking an IPv6 extension, catch it inside `_decode_ipv6` and return the current partial observation with the failure reason. Do not discard known fields.

- [ ] **Step 5: Add malformed-length regression cases**

Add parameterized cases for IPv4 IHL below 20, IPv4 total length below IHL, TCP data offset below 20, truncated UDP, IPv6 zero-length jumbogram, IPv6 AH length beyond the declared payload or 512-byte decoder bound, third VLAN tag, and unsupported datalink. Assert `outcome` and exact `decode_reason`.

Run:

```bash
pytest tests/test_decode_v2.py -q
ruff check src/ibn_monitor/decode.py tests/packet_bytes.py tests/test_decode_v2.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/decode.py tests/packet_bytes.py tests/test_decode_v2.py
git commit -m "feat: decode bounded IPv6 header metadata"
```

---

### Task 7: Stream classic PCAP without buffering payload

**Files:**
- Create: `src/ibn_monitor/pcap.py`
- Create: `tests/pcap_bytes.py`
- Create: `tests/test_pcap_v2.py`

**Interfaces:**
- Consumes: `decode_observation` and `ObservationContext`.
- Produces:

```python
PcapError
iter_pcap_observations(
    path: str | Path,
    *,
    context: ObservationContext,
) -> Iterator[Observation]
```

- [ ] **Step 1: Add deterministic PCAP builders**

```python
# tests/pcap_bytes.py
import struct


def classic_pcap(records, *, datalink=1, endian="<", nanosecond=False):
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1",
        (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1",
        (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nanosecond)]
    output = bytearray(magic)
    output.extend(struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, datalink))
    for seconds, fraction, frame, wire_length in records:
        output.extend(
            struct.pack(
                f"{endian}IIII",
                seconds,
                fraction,
                len(frame),
                wire_length,
            )
        )
        output.extend(frame)
    return bytes(output)
```

- [ ] **Step 2: Write endian, timestamp, rejection, and payload-skip tests**

```python
# tests/test_pcap_v2.py
from io import BytesIO

import pytest

from ibn_monitor.pcap import PcapError, iter_pcap_stream
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from pcap_bytes import classic_pcap
from test_decode_v2 import context


class TrackingStream(BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.read_ranges = []

    def read(self, size=-1):
        start = self.tell()
        data = super().read(size)
        self.read_ranges.append((start, len(data)))
        return data


@pytest.mark.parametrize(("endian", "nanosecond"), [("<", False), (">", True)])
def test_streams_timestamped_observations(endian, nanosecond):
    frame = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    fraction = 500_000_000 if nanosecond else 500_000
    stream = TrackingStream(
        classic_pcap(
            [(1_700_000_000, fraction, frame + b"secret", 1500)],
            endian=endian,
            nanosecond=nanosecond,
        )
    )
    observations = list(iter_pcap_stream(stream, context=context()))
    assert observations[0].captured_at.microsecond == 500_000
    assert observations[0].wire_length == 1500
    packet_start = 24 + 16
    packet_bytes_read = sum(
        length for start, length in stream.read_ranges if start >= packet_start
    )
    assert packet_bytes_read == len(frame)
    assert stream.tell() == len(stream.getvalue())


def test_rejects_pcapng_before_records():
    with pytest.raises(PcapError, match="PCAPNG is not supported"):
        list(iter_pcap_stream(BytesIO(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20), context=context()))


def test_rejects_unsupported_datalink_before_records():
    payload = classic_pcap([], datalink=105)
    with pytest.raises(PcapError, match="unsupported datalink 105"):
        list(iter_pcap_stream(BytesIO(payload), context=context()))
```

- [ ] **Step 3: Run the tests and verify the PCAP module is missing**

Run:

```bash
pytest tests/test_pcap_v2.py -q
```

Expected: collection ERROR for `ibn_monitor.pcap`.

- [ ] **Step 4: Implement global/record parsing and a lazy record reader**

```python
class PcapError(ValueError):
    pass


_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_SUPPORTED_DATALINKS = {1, 101, 113, 276}


class _RecordReader:
    def __init__(self, stream: BinaryIO, captured_length: int, wire_length: int):
        self._stream = stream
        self._captured_length = captured_length
        self._cache = bytearray()
        self.wire_length = wire_length

    def prefix(self, length: int) -> bytes:
        target = min(length, self._captured_length, MAX_HEADER_BYTES)
        missing = target - len(self._cache)
        if missing > 0:
            data = self._stream.read(missing)
            if len(data) != missing:
                raise PcapError("truncated packet record")
            self._cache.extend(data)
        return bytes(self._cache[:target])

    def finish(self) -> None:
        remaining = self._captured_length - len(self._cache)
        if remaining:
            self._stream.seek(remaining, 1)
```

`iter_pcap_stream` must:

1. Read exactly 24 global-header bytes.
2. Reject PCAPNG magic and unknown magic.
3. Require version 2.4, positive snaplen no greater than 16 MiB, and a supported datalink.
4. Read each 16-byte record header.
5. Validate `incl_len <= snaplen` and `orig_len >= incl_len`.
6. Require a seekable stream. Save the record-data offset, seek to end and reject when `record_data_offset + incl_len` exceeds file length, then seek back without reading record bytes.
7. Construct `_RecordReader`, replace `context.captured_at` from record time, decode immediately, call `finish()` in `finally`, and yield the observation.
8. Reject partial record headers or records that extend beyond EOF.

`iter_pcap_observations(path, context=...)` opens the path in binary mode and yields from `iter_pcap_stream`.

The `TrackingStream.read_ranges` assertion above proves the decoder reads exactly the Ethernet, IPv4, and TCP headers. The final stream position proves `finish()` seeks across the unread payload to the next record boundary.

- [ ] **Step 5: Run focused checks**

Run:

```bash
pytest tests/test_pcap_v2.py tests/test_decode_v2.py -q
ruff check src/ibn_monitor/pcap.py tests/pcap_bytes.py tests/test_pcap_v2.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/pcap.py tests/pcap_bytes.py tests/test_pcap_v2.py
git commit -m "feat: stream header-only classic pcap replay"
```

---

### Task 8: Add the deterministic violation-episode state machine

**Files:**
- Modify: `src/ibn_monitor/models.py`
- Create: `src/ibn_monitor/episodes.py`
- Create: `tests/test_episodes_v2.py`

**Interfaces:**
- Consumes: matched `PolicyRule` and `Observation`.
- Produces:

```python
EpisodeKey
EpisodeTransition
EpisodeTracker.observe(...)
EpisodeTracker.advance(...)
EpisodeTracker.close_all(...)
EpisodeTracker.snapshot()
```

- [ ] **Step 1: Add failing lifecycle and merge tests**

```python
# tests/test_episodes_v2.py
from dataclasses import replace

from factories import observation, policy_rule
from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker


def tracker(capacity=10):
    ids = iter(["episode-1", "episode-2", "episode-3"])
    return EpisodeTracker(
        EpisodeSettings(capacity, idle_seconds=30, progress_seconds=60),
        id_factory=lambda: next(ids),
    )


def test_start_progress_and_idle_close():
    state = tracker()
    start = state.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    assert [item.phase for item in start] == ["start"]
    state.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=40,
    )
    assert state.advance(59) == ()
    assert [item.phase for item in state.advance(60)] == ["progress"]
    assert [item.close_reason for item in state.advance(70)] == ["idle"]


def test_capture_points_merge_but_retain_per_point_counts():
    state = tracker()
    state.observe(
        policy_rule(),
        observation(capture_point="wan"),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    state.observe(
        policy_rule(),
        observation(capture_point="lan", wire_length=70),
        policy_revision="a" * 64,
        lifecycle_time=1,
    )
    close = state.close_all("source_exhausted", lifecycle_time=2)[0]
    assert close.observation_count == 2
    assert close.observed_bytes == 130
    assert close.per_capture_point == (
        ("lan", 1, 70),
        ("wan", 1, 60),
    )


def test_capacity_evicts_least_recent_episode_before_new_start():
    state = tracker(capacity=1)
    state.observe(
        policy_rule(id="R1"),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    emitted = state.observe(
        policy_rule(id="R2"),
        replace(observation(), destination_port=443),
        policy_revision="a" * 64,
        lifecycle_time=1,
    )
    assert [(item.phase, item.close_reason) for item in emitted] == [
        ("close", "capacity_evicted"),
        ("start", None),
    ]
```

- [ ] **Step 2: Run the tests and verify episode types are missing**

Run:

```bash
pytest tests/test_episodes_v2.py -q
```

Expected: collection ERROR for `ibn_monitor.episodes`.

- [ ] **Step 3: Add frozen episode records to `models.py`**

```python
EpisodePhase = Literal["start", "progress", "close"]
EpisodeCloseReason = Literal[
    "idle",
    "capacity_evicted",
    "policy_reload",
    "source_exhausted",
    "shutdown",
]


@dataclass(frozen=True, slots=True)
class EpisodeKey:
    policy_revision: str
    rule_id: str
    ip_version: int | None
    source: Address | None
    destination: Address | None
    protocol: str | None
    source_port: int | None
    destination_port: int | None
    icmp_type: int | None
    icmp_code: int | None
    fields: int
    decode_reason: str | None


@dataclass(frozen=True, slots=True)
class EpisodeTransition:
    episode_id: str
    phase: EpisodePhase
    key: EpisodeKey
    rule: PolicyRule
    first_observed_at: datetime
    last_observed_at: datetime
    lifecycle_time: float
    observation_count: int
    observed_bytes: int
    late_observation_count: int
    per_capture_point: tuple[tuple[str, int, int], ...]
    truncated: bool = False
    close_reason: EpisodeCloseReason | None = None
```

- [ ] **Step 4: Implement key construction and private mutable state**

```python
@dataclass(frozen=True, slots=True)
class EpisodeSettings:
    capacity: int
    idle_seconds: float
    progress_seconds: float


class _EpisodeState:
    def __init__(self, episode_id, key, rule, observation, lifecycle_time):
        self.episode_id = episode_id
        self.key = key
        self.rule = rule
        self.first_observed_at = observation.captured_at
        self.last_observed_at = observation.captured_at
        self.last_lifecycle_time = lifecycle_time
        self.last_progress_time = lifecycle_time
        self.observation_count = 1
        self.observed_bytes = observation.wire_length
        self.late_observation_count = int(observation.late)
        self.per_point = {
            observation.capture_point: [1, observation.wire_length]
        }
```

`EpisodeTracker` stores `OrderedDict[EpisodeKey, _EpisodeState]`. Key construction includes policy revision supplied to `observe`:

```python
def observe(
    self,
    rule: PolicyRule,
    observation: Observation,
    *,
    policy_revision: str,
    lifecycle_time: float,
) -> tuple[EpisodeTransition, ...]:
```

Do not use capture point in `EpisodeKey`. For a late update, increment counts but never move `first_observed_at` or `last_observed_at` backward.

- [ ] **Step 5: Implement deterministic transitions**

`advance(now)` iterates a snapshot of insertion/LRU order. Idle close takes precedence over progress. `observe` moves updated state to the end. Capacity eviction pops `last=False` and emits a truncated close before the new start. `close_all` emits in current LRU order and clears state. Every emitted `per_capture_point` tuple is sorted by point name.

`snapshot()` returns frozen `EpisodeTransition` values with phase `progress` but does not modify checkpoint timers.

- [ ] **Step 6: Add partial-key and reload-close tests**

Assert two otherwise identical observations with different `fields` / `decode_reason` create different episodes. Assert `close_all("policy_reload", ...)` emits close transitions and empties `snapshot()`.

Run:

```bash
pytest tests/test_episodes_v2.py -q
ruff check src/ibn_monitor/episodes.py src/ibn_monitor/models.py tests/test_episodes_v2.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ibn_monitor/models.py src/ibn_monitor/episodes.py tests/test_episodes_v2.py
git commit -m "feat: aggregate v2 violation episodes"
```

---

### Task 9: Add schema-v2 evidence envelopes and sequencing

**Files:**
- Modify: `src/ibn_monitor/models.py`
- Modify: `src/ibn_monitor/events.py`
- Create: `tests/test_evidence_v2.py`

**Interfaces:**
- Consumes: `EpisodeTransition`.
- Produces:

```python
EvidenceEnvelope
EvidenceSequencer.wrap_episode(
    transition: EpisodeTransition,
    *,
    emitted_at: datetime,
) -> EvidenceEnvelope
```

- [ ] **Step 1: Write the exact wire-shape test**

```python
# tests/test_evidence_v2.py
from datetime import UTC, datetime

from factories import observation, policy_rule
from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.events import EvidenceSequencer


def test_episode_envelope_has_stable_identity_and_wire_shape():
    tracker = EpisodeTracker(
        EpisodeSettings(10, 30, 60),
        id_factory=lambda: "episode-1",
    )
    transition = tracker.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )[0]
    sequencer = EvidenceSequencer("sensor-1", "boot-1")
    event = sequencer.wrap_episode(
        transition,
        emitted_at=datetime(2026, 7, 23, tzinfo=UTC),
    )
    assert event.to_dict() == {
        "schema_version": 2,
        "event_id": "boot-1:1",
        "event_type": "violation_episode",
        "sensor_id": "sensor-1",
        "boot_id": "boot-1",
        "sequence": 1,
        "emitted_at": "2026-07-23T00:00:00+00:00",
        "policy_revision": "a" * 64,
        "payload": {
            "episode_id": "episode-1",
            "phase": "start",
            "rule": {
                "id": "DEV-DB",
                "description": "development must not reach production database",
                "severity": "critical",
                "enforcement": "nftables_drop_candidate",
            },
            "flow": {
                "ip_version": 4,
                "source": "10.20.5.14",
                "destination": "10.50.10.8",
                "protocol": "tcp",
                "source_port": 40000,
                "destination_port": 5432,
                "icmp_type": None,
                "icmp_code": None,
                "fields": 127,
                "decode_reason": None,
            },
            "first_observed_at": "2026-07-23T00:00:00+00:00",
            "last_observed_at": "2026-07-23T00:00:00+00:00",
            "duration_seconds": 0.0,
            "observation_count": 1,
            "observed_bytes": 60,
            "late_observation_count": 0,
            "per_capture_point": {
                "pcap": {"observations": 1, "observed_bytes": 60}
            },
            "truncated": False,
            "close_reason": None,
        },
    }
```

- [ ] **Step 2: Run the test and verify the sequencer is missing**

Run:

```bash
pytest tests/test_evidence_v2.py -q
```

Expected: collection ERROR for `EvidenceSequencer`.

- [ ] **Step 3: Add the frozen envelope and serializer**

```python
# models.py
@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    schema_version: int
    event_id: str
    event_type: str
    sensor_id: str
    boot_id: str
    sequence: int
    emitted_at: datetime
    policy_revision: str | None
    payload: EpisodeTransition

    def to_dict(self) -> dict[str, object]:
        transition = self.payload
        key = transition.key
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "sensor_id": self.sensor_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "emitted_at": self.emitted_at.isoformat(),
            "policy_revision": self.policy_revision,
            "payload": {
                "episode_id": transition.episode_id,
                "phase": transition.phase,
                "rule": {
                    "id": transition.rule.id,
                    "description": transition.rule.description,
                    "severity": transition.rule.severity,
                    "enforcement": transition.rule.enforcement,
                },
                "flow": {
                    "ip_version": key.ip_version,
                    "source": str(key.source) if key.source else None,
                    "destination": str(key.destination) if key.destination else None,
                    "protocol": key.protocol,
                    "source_port": key.source_port,
                    "destination_port": key.destination_port,
                    "icmp_type": key.icmp_type,
                    "icmp_code": key.icmp_code,
                    "fields": key.fields,
                    "decode_reason": key.decode_reason,
                },
                "first_observed_at": transition.first_observed_at.isoformat(),
                "last_observed_at": transition.last_observed_at.isoformat(),
                "duration_seconds": max(
                    0.0,
                    (
                        transition.last_observed_at
                        - transition.first_observed_at
                    ).total_seconds(),
                ),
                "observation_count": transition.observation_count,
                "observed_bytes": transition.observed_bytes,
                "late_observation_count": transition.late_observation_count,
                "per_capture_point": {
                    name: {
                        "observations": observations,
                        "observed_bytes": observed_bytes,
                    }
                    for name, observations, observed_bytes
                    in transition.per_capture_point
                },
                "truncated": transition.truncated,
                "close_reason": transition.close_reason,
            },
        }
```

- [ ] **Step 4: Add the replay sequencer without changing v1 event code**

```python
# events.py addition
class EvidenceSequencer:
    def __init__(self, sensor_id: str, boot_id: str) -> None:
        self._sensor_id = sensor_id
        self._boot_id = boot_id
        self._next_sequence = 1

    def wrap_episode(
        self,
        transition: EpisodeTransition,
        *,
        emitted_at: datetime,
    ) -> EvidenceEnvelope:
        sequence = self._next_sequence
        self._next_sequence += 1
        return EvidenceEnvelope(
            schema_version=2,
            event_id=f"{self._boot_id}:{sequence}",
            event_type="violation_episode",
            sensor_id=self._sensor_id,
            boot_id=self._boot_id,
            sequence=sequence,
            emitted_at=emitted_at,
            policy_revision=transition.key.policy_revision,
            payload=transition,
        )
```

- [ ] **Step 5: Enforce the 256-KiB event bound**

Add a private dictionary serializer plus the typed public wrapper in `events.py`:

```python
MAX_EVIDENCE_LINE_BYTES = 262_144


def _serialize_evidence_dict(payload: dict[str, object]) -> str:
    line = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len((line + "\n").encode("utf-8")) > MAX_EVIDENCE_LINE_BYTES:
        raise ValueError("evidence event exceeds 262144 bytes")
    return line


def serialize_evidence(event: EvidenceEnvelope) -> str:
    return _serialize_evidence_dict(event.to_dict())
```

Test the exact boundary through `_serialize_evidence_dict`: use binary search to find the largest ASCII string value whose encoded line plus newline is at most 262,144 bytes, assert it succeeds, then append one character and assert the documented `ValueError`. Keep the public wrapper wire-shape assertion on a real `EvidenceEnvelope`.

Run:

```bash
pytest tests/test_evidence_v2.py tests/test_events.py -q
ruff check src/ibn_monitor/models.py src/ibn_monitor/events.py tests/test_evidence_v2.py
```

Expected: PASS; v1 event wire tests remain unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/models.py src/ibn_monitor/events.py tests/test_evidence_v2.py
git commit -m "feat: add v2 evidence envelopes"
```

---

### Task 10: Orchestrate deterministic event-time replay

**Files:**
- Create: `src/ibn_monitor/replay.py`
- Create: `tests/test_replay_v2.py`
- Modify: `tests/factories.py`

**Interfaces:**
- Consumes: `PolicyV2Config`, classic PCAP observations, `CompiledPolicy`, `EpisodeTracker`, `EvidenceSequencer`.
- Produces:

```python
ReplaySummary
replay_pcap(
    config: PolicyV2Config,
    pcap_path: str | Path,
    output: TextIO,
    *,
    boot_id: str,
) -> ReplaySummary
```

- [ ] **Step 1: Write replay lifecycle, all-match, and late-arrival tests**

```python
# tests/test_replay_v2.py
import json

from factories import v2_config
from pcap_bytes import classic_pcap
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from ibn_monitor.replay import replay_pcap


def record(seconds, destination_port=5432):
    frame = ethernet_frame(
        ipv4_packet(tcp_header(destination_port=destination_port), protocol=6)
    )
    return (seconds, 0, frame, len(frame))


def test_replay_emits_start_and_source_exhausted_close(tmp_path):
    config = v2_config()
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([record(10), record(11)]))
    output = tmp_path / "events.jsonl"
    with output.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, pcap, stream, boot_id="replay-1")
    events = [json.loads(line) for line in output.read_text().splitlines()]
    assert [event["payload"]["phase"] for event in events] == ["start", "close"]
    assert events[-1]["payload"]["close_reason"] == "source_exhausted"
    assert events[-1]["payload"]["observation_count"] == 2
    assert summary.observations == 2
    assert summary.matched_observations == 2
    assert summary.episodes_started == 1
    assert summary.episodes_closed == 1


def test_replay_marks_arrival_older_than_finalized_watermark(tmp_path):
    config = v2_config()
    pcap = tmp_path / "late.pcap"
    pcap.write_bytes(classic_pcap([record(10), record(20), record(5)]))
    output = tmp_path / "events.jsonl"
    with output.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, pcap, stream, boot_id="replay-2")
    assert summary.late_observations == 1
```

Add the exact revision-safe factory to `tests/factories.py`:

```python
def v2_config(*, rules: tuple[PolicyRule, ...] | None = None) -> PolicyV2Config:
    path = Path(__file__).parents[1] / "config" / "policy.v2.example.json"
    base = load_v2_config(path)
    selected_rules = base.rules if rules is None else rules
    provisional = replace(
        base,
        rules=selected_rules,
        policy_revision=canonical_policy_revision(selected_rules),
        config_revision="",
    )
    return replace(
        provisional,
        config_revision=canonical_config_revision(provisional),
    )
```

Import `Path`, `replace`, `PolicyV2Config`, and the three config functions alongside the existing factory imports.

- [ ] **Step 2: Run the tests and verify replay is missing**

Run:

```bash
pytest tests/test_replay_v2.py -q
```

Expected: collection ERROR for `ibn_monitor.replay`.

- [ ] **Step 3: Implement the frozen summary and JSONL emission**

```python
@dataclass(frozen=True, slots=True)
class ReplaySummary:
    observations: int
    complete_observations: int
    partial_observations: int
    undecodable_observations: int
    late_observations: int
    matched_observations: int
    rule_matches: int
    episodes_started: int
    episodes_progressed: int
    episodes_closed: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)
```

Use a private mutable counter object during processing and freeze it at return. `_write_transitions` wraps every transition with `EvidenceSequencer`, uses `serialize_evidence`, writes one line, and increments phase totals.

- [ ] **Step 4: Implement the two-second watermark orderer**

```python
def _epoch(observation: Observation) -> float:
    return observation.captured_at.timestamp()


def replay_pcap(config, pcap_path, output, *, boot_id):
    policy = compile_policy(config.rules, config.policy_revision)
    episode_sequence = count(1)
    tracker = EpisodeTracker(
        EpisodeSettings(
            config.episodes.capacity,
            config.episodes.idle_seconds,
            config.episodes.progress_seconds,
        ),
        id_factory=lambda: (
            f"{boot_id}:episode:{next(episode_sequence)}"
        ),
    )
    sequencer = EvidenceSequencer(config.sensor.id, boot_id)
    heap: list[tuple[float, int, Observation]] = []
    max_seen = float("-inf")
    finalized_watermark = float("-inf")
    ordinal = 0
```

For each PCAP observation:

1. Increment outcome totals.
2. If its event time is older than `finalized_watermark`, replace it with `late=True` and process it at `finalized_watermark` without moving existing episode first/last times backward.
3. Otherwise push `(event_time, ordinal, observation)` into the heap.
4. Advance `max_seen` and compute `watermark = max_seen - replay_lateness_seconds`.
5. Pop/process every heap item with event time `<= watermark` in timestamp/ordinal order.
6. Set `finalized_watermark = max(finalized_watermark, watermark)`.

Import `count` from `itertools`. Processing one observation first calls `tracker.advance(lifecycle_time)`, then `evaluate_policy`, then `tracker.observe` for every match in rule-ID order, always passing `policy_revision=config.policy_revision`. Count one `matched_observation` when at least one rule matches and count every rule in `rule_matches`.

`_write_transitions` derives replay emission time without consulting the wall clock:

```python
def _write_transitions(transitions, sequencer, output, counters):
    for transition in transitions:
        event = sequencer.wrap_episode(
            transition,
            emitted_at=datetime.fromtimestamp(transition.lifecycle_time, UTC),
        )
        output.write(serialize_evidence(event) + "\n")
        counters.record_phase(transition.phase)
```

At EOF, pop remaining observations in timestamp order, advance lifecycle monotonically with `max(last_lifecycle, event_time)`, then call `close_all("source_exhausted", ...)`. If the PCAP contains no observations, return all-zero totals and write no evidence.

Use the replay observation context:

```python
ObservationContext(
    captured_at=datetime.fromtimestamp(0, UTC),
    monotonic_at=None,
    sensor_id=config.sensor.id,
    source_generation=f"replay:{boot_id}",
    capture_point="pcap",
    interface=None,
    direction="unknown",
)
```

- [ ] **Step 5: Add deterministic injected-ID tests**

Run the same replay twice with the same explicit `boot_id` and assert byte-identical JSONL. Run with a different boot ID and assert only `boot_id` / `event_id` differ while phases, counts, times, flow, rule, and sequence remain equal.

Add an all-match replay test using a `PolicyV2Config` whose two enabled rules both match `record(10)`. Assert two start and two close envelopes appear in rule-ID order, `matched_observations == 1`, and `rule_matches == 2`. The `v2_config` factory must recompute both canonical revisions after any rule override.

Run:

```bash
pytest tests/test_replay_v2.py tests/test_episodes_v2.py tests/test_policy_v2.py -q
ruff check src/ibn_monitor/replay.py tests/test_replay_v2.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ibn_monitor/replay.py tests/test_replay_v2.py tests/factories.py
git commit -m "feat: replay v2 policies over classic pcap"
```

---

### Task 11: Expose v2 validate, check, migration, and replay CLI flows

**Files:**
- Modify: `src/ibn_monitor/cli.py:21-185`
- Modify: `tests/test_cli.py`
- Create: `tests/test_cli_v2.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes every Phase 1 pure module.
- Produces public commands:

```text
ibn-monitor validate --config PATH [--format human|json] [--strict]
ibn-monitor check --config PATH ... [--format human|json]
ibn-monitor migrate-policy --config V1 --output V2 --sensor-id ID --topology ... --capture-point NAME=IFACE
ibn-monitor replay --config V2 --pcap FILE --output EVENTS --summary-output PATH|-
```

- [ ] **Step 1: Write v2 CLI contract tests**

```python
# tests/test_cli_v2.py
import json

from ibn_monitor.cli import main


def test_validate_v2_reports_revision(v2_policy_path, capsys):
    assert main(["validate", "--config", str(v2_policy_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["version"] == 2
    assert len(payload["policy_revision"]) == 64


def test_check_v2_returns_one_for_violation(v2_policy_path, capsys):
    code = main(
        [
            "check",
            "--config",
            str(v2_policy_path),
            "--source",
            "10.20.5.14",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
            "--source-port",
            "40000",
            "--destination-port",
            "5432",
            "--format",
            "json",
        ]
    )
    assert code == 1
    assert json.loads(capsys.readouterr().out)["rules"][0]["id"] == "DEV-DB"


def test_replay_requires_v2_and_separate_output_paths(
    v2_policy_path, pcap_path, tmp_path, capsys
):
    events = tmp_path / "events.jsonl"
    summary = tmp_path / "summary.json"
    assert main(
        [
            "replay",
            "--config",
            str(v2_policy_path),
            "--pcap",
            str(pcap_path),
            "--output",
            str(events),
            "--summary-output",
            str(summary),
            "--boot-id",
            "test-replay",
        ]
    ) == 0
    assert events.read_text(encoding="utf-8")
    assert json.loads(summary.read_text(encoding="utf-8"))["observations"] >= 1
```

Add a migration CLI test proving the command refuses to overwrite an existing output and never modifies the input.

- [ ] **Step 2: Run the tests and verify parser choices are missing**

Run:

```bash
pytest tests/test_cli_v2.py -q
```

Expected: FAIL because `replay` / `migrate-policy` parser choices do not exist.

- [ ] **Step 3: Extend the parser without changing live/render arguments**

Add `--format` and `--strict` to `validate`, `--format` to `check`, and new subparsers:

```python
migrate_parser = subparsers.add_parser(
    "migrate-policy", help="Convert an explicit v1 policy to a v2 candidate"
)
migrate_parser.add_argument("--config", required=True)
migrate_parser.add_argument("--output", required=True)
migrate_parser.add_argument("--sensor-id", required=True)
migrate_parser.add_argument(
    "--topology", choices=["gateway", "mirror", "host"], required=True
)
migrate_parser.add_argument(
    "--capture-point",
    required=True,
    metavar="NAME=INTERFACE",
)

replay_parser = subparsers.add_parser(
    "replay", help="Evaluate classic PCAP using v2 event-time semantics"
)
replay_parser.add_argument("--config", required=True)
replay_parser.add_argument("--pcap", required=True)
replay_parser.add_argument("--output", required=True)
replay_parser.add_argument("--summary-output", default="-")
replay_parser.add_argument("--boot-id")
```

- [ ] **Step 4: Route validate/check by detected version**

For `version == 1`, call the existing code unchanged. For `version == 2`:

- `validate` calls `validate_v2_config`, prints diagnostics in requested format, and returns 2 for errors or strict warnings.
- `check` loads v2, validates CLI IPs with `ip_address`, constructs a complete synthetic `Observation` and compiled policy, prints all match explanations, and returns 1 on any match.
- Any other version returns 2 with an unsupported-version error.

Build the synthetic observation from only the fields the CLI actually knows:

```python
def _synthetic_observation(args, sensor_id: str) -> Observation:
    source = ip_address(args.source)
    destination = ip_address(args.destination)
    if source.version != destination.version:
        raise ConfigError("source and destination IP versions must match")
    fields = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
        | FieldPresence.PROTOCOL
    )
    if args.source_port is not None:
        fields |= FieldPresence.SOURCE_PORT
    if args.destination_port is not None:
        fields |= FieldPresence.DESTINATION_PORT
    return Observation(
        captured_at=datetime.now(UTC),
        monotonic_at=None,
        sensor_id=sensor_id,
        source_generation="synthetic-check",
        capture_point="synthetic",
        interface=None,
        direction="unknown",
        wire_length=0,
        ip_version=source.version,
        source=source,
        destination=destination,
        protocol=args.protocol.lower(),
        source_port=args.source_port,
        destination_port=args.destination_port,
        fields=fields,
        outcome="complete",
    )
```

Extract small private handlers (`_validate`, `_check`, `_migrate`, `_replay`) so `main` remains a composition/error boundary.

- [ ] **Step 5: Implement safe migration and replay file handling**

`migrate-policy`:

- Parse `NAME=INTERFACE` once and reject empty halves.
- Refuse when output exists.
- Call `migrate_v1_policy`.
- Print diagnostics and return 2 on ambiguity.
- Validate the candidate with the v2 validator before writing.
- Write UTF-8 JSON with indent 2 and trailing newline.

`replay`:

- Require config version 2.
- Refuse output/summary paths that resolve to the same file.
- Refuse to overwrite either file.
- Generate `boot_id = str(uuid.uuid4())` unless supplied.
- Write events and summary using UTF-8 with newline.
- When `--summary-output -` is used, write only the summary JSON to stdout.

- [ ] **Step 6: Preserve v1 CLI regression tests**

Run:

```bash
pytest tests/test_cli.py tests/test_cli_v2.py -q
```

Expected:

- Existing v1 validate output remains version 1.
- Existing v1 match still returns 2 during the transitional phase.
- V2 match returns 1.
- Live `run` and `render-nftables` parser behavior is unchanged.

- [ ] **Step 7: Add focused Make targets**

Add:

```make
validate-v2:
	ibn-monitor validate --config config/policy.v2.example.json --strict

replay-v2:
	ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap --output build/replay-v2.jsonl --summary-output -
```

Do not replace the existing v1 `validate`, `check`, `pcap`, or `nftables` targets in Phase 1.

- [ ] **Step 8: Run full tests and lint**

Run:

```bash
pytest -q
ruff check .
```

Expected: PASS. The clean implementation worktree must not include the unrelated long-line edit currently present in the user's main worktree.

- [ ] **Step 9: Commit**

```bash
git add src/ibn_monitor/cli.py tests/test_cli.py tests/test_cli_v2.py Makefile
git commit -m "feat: expose v2 policy and replay commands"
```

---

### Task 12: Document Phase 1 and run the release-quality regression

**Files:**
- Modify: `README.md`
- Modify: `CONTEXT.md`
- Modify: `AGENTS.md`
- Modify: `scripts/generate_test_pcap.py`

**Interfaces:**
- Documents the temporary v1/v2 boundary and ensures new test fixtures do not require Scapy.
- Does not change runtime APIs.

- [ ] **Step 1: Replace the test-PCAP generator's Scapy dependency**

Duplicate the short `struct.pack` Ethernet/IPv4/TCP/classic-PCAP builders in `scripts/generate_test_pcap.py`; scripts and production code must not import from tests. Generate one matching TCP SYN and one allowed TCP SYN with deterministic timestamps. Preserve output path `test-traffic.pcap`.

Run:

```bash
python scripts/generate_test_pcap.py
ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap --output build/replay-v2.jsonl --summary-output -
```

Expected: summary reports 2 observations, 1 matched observation, 1 episode start, and 1 episode close.

- [ ] **Step 2: Update the domain glossary**

Add exact terms:

- **Observation**: immutable complete/partial/undecodable L3/L4 metadata record; replaces packet-shaped v1 metadata in v2.
- **Compiled policy**: immutable normalized predicate IR with a canonical policy revision.
- **Violation episode**: rule-plus-flow lifecycle aggregation with start/progress/close transitions.
- **Evidence envelope**: schema-v2 sequenced JSONL wrapper.
- **Replay watermark**: maximum seen capture time minus allowed lateness.

Keep v1 `PacketMetadata` / `Rule` entries labeled as transitional until Phase 2.

- [ ] **Step 3: Update README and AGENTS architecture**

Document:

- V2 explicit policy example and migration command.
- V2 validate/check exit codes.
- Separate classic-PCAP `replay` command and output paths.
- PCAPNG rejection.
- No v2 Scapy import.
- Live `run` and nftables remain v1 until later phases.
- New modules and shared v2 test factories.

Do not claim AF_PACKET live capture, durable v2 journal, split HTTP, or topology-aware nftables is implemented in Phase 1.

- [ ] **Step 4: Verify the existing Scapy test boundary**

Do not modify `tests/conftest.py`: it still configures Scapy for v1 tests. Confirm no new global fixture or v2-module import was added there. New v2 decoder/replay fixtures belong in `tests/factories.py` and remain stdlib-only.

- [ ] **Step 5: Run the complete verification matrix**

Run:

```bash
pytest -q
pytest tests/test_config_v2.py tests/test_policy_v2.py tests/test_decode_v2.py tests/test_pcap_v2.py tests/test_episodes_v2.py tests/test_evidence_v2.py tests/test_replay_v2.py tests/test_cli_v2.py -q
ruff check .
python -m pip wheel . --no-deps --wheel-dir build/wheels
```

Expected:

- All v1 and v2 tests PASS.
- Ruff reports no findings.
- The wheel includes both `policy.schema.json` and `policy-v2.schema.json`.

Inspect the wheel:

```bash
python -c "import glob, zipfile; names=zipfile.ZipFile(glob.glob('build/wheels/*.whl')[0]).namelist(); print('\n'.join(name for name in names if name.endswith('.schema.json')))"
```

Expected: both schema filenames appear under `ibn_monitor/`.

- [ ] **Step 6: Review the transitional boundary**

Run:

```bash
rg -n "from scapy|import scapy" src/ibn_monitor
```

Expected: Scapy imports exist only in the untouched v1 `capture.py`. New `policy.py`, `decode.py`, `pcap.py`, `episodes.py`, `replay.py`, and v2 paths in `config.py` / `cli.py` contain no Scapy references.

Run:

```bash
git diff --check
git status --short
```

Expected: only intended Phase 1 files are modified before the final commit.

- [ ] **Step 7: Commit**

```bash
git add README.md CONTEXT.md AGENTS.md scripts/generate_test_pcap.py
git commit -m "docs: document v2 core and replay phase"
```

---

## Phase 1 completion criteria

- V2 policy/config is explicit, schema-validated, semantically validated, revision-hashed, and migratable from unambiguous v1 input.
- Compiled matching reports every prohibited assertion and never treats unknown partial fields as wildcards.
- The decoder handles approved IPv4/IPv6/link formats within fixed bounds and exposes no payload bytes.
- Classic PCAP streams by header prefix and skips payload bytes without loading complete records.
- Episodes emit deterministic start/progress/close transitions with capacity and late-observation accounting.
- Replay emits schema-v2 sequenced JSONL and a machine-readable summary.
- V2 validate/check/migrate/replay CLI contracts work with exact exit codes and safe output handling.
- The existing v1 live/render path remains test-green and behavior-compatible.
- Full pytest, Ruff, and package-content checks pass from a clean worktree.
- Phase 2 can consume `Observation`, `PolicyV2Config`, `CompiledPolicy`, `EpisodeTracker`, and `EvidenceSequencer` without renaming their public interfaces.

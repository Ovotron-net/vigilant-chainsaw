from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from importlib import resources
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema

from .models import (
    Action,
    Diagnostic,
    EnforcementDisposition,
    Network,
    PolicyMatch,
    PolicyProtocol,
    PolicyRule,
    Protocol,
    Rule,
    Severity,
)

Topology = Literal["gateway", "mirror", "host"]
CaptureDirection = Literal["inbound", "outbound", "both"]

_DIRECTION_DEFAULT: dict[Topology, CaptureDirection] = {
    "gateway": "inbound",
    "mirror": "inbound",
    "host": "both",
}


class ConfigError(ValueError):
    """Raised when the monitor configuration is invalid."""


@dataclass(frozen=True, slots=True)
class SensorConfig:
    interface: str | None
    bpf_filter: str
    promiscuous: bool


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    file: str
    max_bytes: int
    backup_count: int


@dataclass(frozen=True, slots=True)
class HealthConfig:
    enabled: bool
    bind: str
    port: int


@dataclass(frozen=True, slots=True)
class NotificationConfig:
    webhook_url_env: str | None
    timeout_seconds: float
    minimum_severity: str
    deduplication_seconds: int


@dataclass(frozen=True, slots=True)
class AppConfig:
    version: int
    sensor: SensorConfig
    logging: LoggingConfig
    health: HealthConfig
    notifications: NotificationConfig
    rules: tuple[Rule, ...]


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


_PROTOCOLS: frozenset[str] = frozenset({"any", "tcp", "udp", "icmp"})
_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
_ACTIONS: frozenset[str] = frozenset({"alert", "drop"})


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    schema_text = (
        resources.files("ibn_monitor").joinpath("policy.schema.json").read_text(encoding="utf-8")
    )
    return json.loads(schema_text)


@lru_cache(maxsize=1)
def _load_v2_schema() -> dict[str, Any]:
    schema_text = (
        resources.files("ibn_monitor")
        .joinpath("policy-v2.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(schema_text)


def _validate_schema(raw: Any) -> None:
    validator = jsonschema.Draft202012Validator(_load_schema())
    errors = sorted(validator.iter_errors(raw), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "root"
        raise ConfigError(f"Policy does not match schema at {location}: {error.message}")


def _read_json(path: str | Path) -> Any:
    config_path = Path(path)
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {config_path}: {exc}") from exc


def _as_protocol(value: str) -> Protocol:
    normalized = value.lower()
    if normalized not in _PROTOCOLS:
        raise ConfigError(f"protocol is invalid: {value}")
    return cast(Protocol, normalized)


def _as_severity(value: str) -> Severity:
    normalized = value.lower()
    if normalized not in _SEVERITIES:
        raise ConfigError(f"severity is invalid: {value}")
    return cast(Severity, normalized)


def _as_action(value: str) -> Action:
    normalized = value.lower()
    if normalized not in _ACTIONS:
        raise ConfigError(f"action is invalid: {value}")
    return cast(Action, normalized)


def _sensor(data: dict[str, Any]) -> SensorConfig:
    return SensorConfig(
        interface=data.get("interface"),
        bpf_filter=data.get("bpf_filter", "ip or ip6"),
        promiscuous=data.get("promiscuous", False),
    )


def _logging(data: dict[str, Any]) -> LoggingConfig:
    return LoggingConfig(
        file=data.get("file", "events.jsonl"),
        max_bytes=data.get("max_bytes", 10_485_760),
        backup_count=data.get("backup_count", 5),
    )


def _health(data: dict[str, Any]) -> HealthConfig:
    return HealthConfig(
        enabled=data.get("enabled", True),
        bind=data.get("bind", "127.0.0.1"),
        port=data.get("port", 9108),
    )


def _notifications(data: dict[str, Any]) -> NotificationConfig:
    return NotificationConfig(
        webhook_url_env=data.get("webhook_url_env"),
        timeout_seconds=float(data.get("timeout_seconds", 3)),
        minimum_severity=str(data.get("minimum_severity", "high")).lower(),
        deduplication_seconds=int(data.get("deduplication_seconds", 60)),
    )


def _rule(data: dict[str, Any], index: int) -> Rule:
    rule_id = data["id"]
    description = data.get("description", rule_id)
    enabled = data.get("enabled", True)

    source_values = data.get("source_cidrs", [])
    destination_values = data.get("destination_cidrs", [])
    try:
        source_cidrs = tuple(ip_network(item, strict=False) for item in source_values)
        destination_cidrs = tuple(ip_network(item, strict=False) for item in destination_values)
    except ValueError as exc:
        raise ConfigError(f"rules[{index}] contains an invalid CIDR: {exc}") from exc

    return Rule(
        id=rule_id,
        description=description,
        enabled=enabled,
        source_cidrs=source_cidrs,
        destination_cidrs=destination_cidrs,
        protocol=_as_protocol(data.get("protocol", "any")),
        destination_ports=frozenset(data.get("destination_ports", [])),
        severity=_as_severity(data.get("severity", "high")),
        action=_as_action(data.get("action", "alert")),
    )


def _rules(rules_value: list[Any]) -> tuple[Rule, ...]:
    rules = tuple(
        _rule(cast(dict[str, Any], value), index) for index, value in enumerate(rules_value)
    )
    identifiers = [rule.id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ConfigError("Rule IDs must be unique")
    return rules


def load_config(path: str | Path) -> AppConfig:
    raw = _read_json(path)
    _validate_schema(raw)
    data = cast(dict[str, Any], raw)

    return AppConfig(
        version=1,
        sensor=_sensor(cast(dict[str, Any], data.get("sensor", {}))),
        logging=_logging(cast(dict[str, Any], data.get("logging", {}))),
        health=_health(cast(dict[str, Any], data.get("health", {}))),
        notifications=_notifications(cast(dict[str, Any], data.get("notifications", {}))),
        rules=_rules(cast(list[Any], data["rules"])),
    )


def detect_config_version(path: str | Path) -> int:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise ConfigError("root must be an object")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ConfigError("version must be an integer")
    return version


def _rule_wire(rule: PolicyRule) -> dict[str, object]:
    ports: str | list[int] = (
        "any"
        if rule.match.destination_ports is None
        else sorted(rule.match.destination_ports)
    )
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


def runtime_identity_hash(config: PolicyV2Config) -> str:
    """Hash every effective field outside the rule set (restart-only gate)."""
    wire = _config_wire(config)
    wire = {**wire, "rules": []}
    return _sha256(wire)


def _capture_point(raw: dict[str, Any], topology: Topology) -> CapturePointConfig:
    return CapturePointConfig(
        name=raw["name"],
        interface=raw["interface"],
        direction=cast(CaptureDirection, raw.get("direction", _DIRECTION_DEFAULT[topology])),
        promiscuous=bool(raw.get("promiscuous", topology == "mirror")),
    )


def _normalize_cidrs(
    values: list[Any],
    *,
    path: str,
    diagnostics: list[Diagnostic],
) -> tuple[Network, ...]:
    networks: list[Network] = []
    seen: set[str] = set()
    for value in values:
        try:
            network = ip_network(value, strict=False)
        except ValueError as exc:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "rule.invalid_cidr",
                    path,
                    f"invalid CIDR {value!r}: {exc}",
                )
            )
            continue
        key = str(network)
        if key in seen:
            continue
        seen.add(key)
        networks.append(network)
    networks.sort(key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    return tuple(networks)


def _parse_destination_ports(
    match: dict[str, Any], protocol: PolicyProtocol
) -> frozenset[int] | None:
    if protocol not in {"tcp", "udp"}:
        return None
    ports = match.get("destination_ports")
    if ports == "any":
        return None
    return frozenset(int(port) for port in cast(list[Any], ports))


def _is_loopback_bind(value: str) -> bool:
    try:
        return bool(ip_address(value).is_loopback)
    except ValueError:
        return False


def validate_v2_config(path: str | Path) -> ConfigValidation:
    diagnostics: list[Diagnostic] = []
    raw = _read_json(path)
    if not isinstance(raw, dict):
        return ConfigValidation(
            None,
            (
                Diagnostic(
                    "error",
                    "schema.invalid",
                    "/",
                    "root must be an object",
                ),
            ),
        )

    schema = _load_v2_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(raw), key=lambda item: list(item.absolute_path)):
        parts = [str(part) for part in error.absolute_path]
        if error.validator == "required":
            # jsonschema reports the parent object; append the missing property.
            missing = next(
                (item for item in error.validator_value if item not in (error.instance or {})),
                None,
            )
            if missing is not None:
                parts.append(str(missing))
        path = "/" + "/".join(parts) if parts else "/"
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="schema.invalid",
                path=path,
                message=error.message,
            )
        )
    if any(item.severity == "error" for item in diagnostics):
        return ConfigValidation(None, tuple(diagnostics))

    data = cast(dict[str, Any], raw)
    sensor_raw = cast(dict[str, Any], data["sensor"])
    topology = cast(Topology, sensor_raw["topology"])
    capture_points = tuple(
        _capture_point(cast(dict[str, Any], point), topology)
        for point in cast(list[Any], sensor_raw["capture_points"])
    )
    sensor = SensorV2Config(
        id=str(sensor_raw["id"]),
        topology=topology,
        capture_points=capture_points,
    )

    names = [point.name for point in capture_points]
    if len(names) != len(set(names)):
        diagnostics.append(
            Diagnostic(
                "error",
                "sensor.duplicate_capture_point",
                "/sensor/capture_points",
                "capture point names must be unique",
            )
        )
    interfaces = [point.interface for point in capture_points]
    if len(interfaces) != len(set(interfaces)):
        diagnostics.append(
            Diagnostic(
                "error",
                "sensor.duplicate_interface",
                "/sensor/capture_points",
                "capture interfaces must be unique",
            )
        )
    if topology == "mirror" and any(not point.promiscuous for point in capture_points):
        diagnostics.append(
            Diagnostic(
                "error",
                "sensor.mirror_promiscuous",
                "/sensor",
                "mirror topology requires promiscuous capture points",
            )
        )

    processing_raw = cast(dict[str, Any], data.get("processing", {}))
    processing = ProcessingV2Config(
        observation_queue_capacity=int(
            processing_raw.get("observation_queue_capacity", 10_000)
        ),
        queue_recovery_cooldown_seconds=float(
            processing_raw.get("queue_recovery_cooldown_seconds", 30.0)
        ),
        graceful_drain_seconds=float(processing_raw.get("graceful_drain_seconds", 10.0)),
    )

    episodes_raw = cast(dict[str, Any], data.get("episodes", {}))
    episodes = EpisodeV2Config(
        capacity=int(episodes_raw.get("capacity", 10_000)),
        idle_seconds=float(episodes_raw.get("idle_seconds", 30.0)),
        progress_seconds=float(episodes_raw.get("progress_seconds", 60.0)),
        replay_lateness_seconds=float(episodes_raw.get("replay_lateness_seconds", 2.0)),
    )

    journal_raw = cast(dict[str, Any], data.get("journal", {}))
    journal = JournalV2Config(
        file=str(journal_raw.get("file", "events-v2.jsonl")),
        max_bytes=int(journal_raw.get("max_bytes", 10_485_760)),
        backup_count=int(journal_raw.get("backup_count", 5)),
        fsync_interval_seconds=float(journal_raw.get("fsync_interval_seconds", 1.0)),
        emergency_max_events=int(journal_raw.get("emergency_max_events", 1_000)),
        emergency_max_bytes=int(journal_raw.get("emergency_max_bytes", 8_388_608)),
    )

    http_raw = cast(dict[str, Any], data.get("http", {}))
    probe_raw = cast(dict[str, Any], http_raw.get("probe", {}))
    operations_raw = cast(dict[str, Any], http_raw.get("operations", {}))
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
    if not _is_loopback_bind(operations.bind) and not operations.allow_non_loopback:
        diagnostics.append(
            Diagnostic(
                "error",
                "http.operations_non_loopback_unacknowledged",
                "/http/operations/bind",
                "non-loopback operations bind requires allow_non_loopback=true",
            )
        )
    http = HttpV2Config(probe=probe, operations=operations)

    notifications_raw = cast(dict[str, Any], data.get("notifications", {}))
    notifications = NotificationV2Config(
        webhook_url_env=notifications_raw.get("webhook_url_env"),
        timeout_seconds=float(notifications_raw.get("timeout_seconds", 3.0)),
        minimum_severity=_as_severity(
            str(notifications_raw.get("minimum_severity", "high"))
        ),
        max_attempts=int(notifications_raw.get("max_attempts", 5)),
        max_elapsed_seconds=float(notifications_raw.get("max_elapsed_seconds", 60.0)),
        shutdown_drain_seconds=float(notifications_raw.get("shutdown_drain_seconds", 5.0)),
        insecure_allow_http_loopback=bool(
            notifications_raw.get("insecure_allow_http_loopback", False)
        ),
    )

    rules_list: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for index, rule_raw in enumerate(cast(list[Any], data["rules"])):
        rule_data = cast(dict[str, Any], rule_raw)
        rule_id = str(rule_data["id"])
        if rule_id in seen_ids:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "rule.duplicate_id",
                    f"/rules/{index}/id",
                    f"duplicate rule id {rule_id}",
                )
            )
            continue
        seen_ids.add(rule_id)

        match_raw = cast(dict[str, Any], rule_data["match"])
        protocol = cast(PolicyProtocol, str(match_raw["protocol"]).lower())
        source_cidrs = _normalize_cidrs(
            cast(list[Any], match_raw["source_cidrs"]),
            path=f"/rules/{index}/match/source_cidrs",
            diagnostics=diagnostics,
        )
        destination_cidrs = _normalize_cidrs(
            cast(list[Any], match_raw["destination_cidrs"]),
            path=f"/rules/{index}/match/destination_cidrs",
            diagnostics=diagnostics,
        )
        source_versions = {network.version for network in source_cidrs}
        destination_versions = {network.version for network in destination_cidrs}
        if source_cidrs and destination_cidrs and not (source_versions & destination_versions):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "rule.impossible_ip_family",
                    f"/rules/{index}/match",
                    "source and destination CIDRs share no IP family",
                )
            )
        try:
            destination_ports = _parse_destination_ports(match_raw, protocol)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "schema.invalid",
                    f"/rules/{index}/match/destination_ports",
                    str(exc),
                )
            )
            continue

        rules_list.append(
            PolicyRule(
                id=rule_id,
                description=str(rule_data["description"]),
                enabled=bool(rule_data["enabled"]),
                match=PolicyMatch(
                    source_cidrs=source_cidrs,
                    destination_cidrs=destination_cidrs,
                    protocol=protocol,
                    destination_ports=destination_ports,
                ),
                severity=_as_severity(str(rule_data["severity"])),
                enforcement=cast(EnforcementDisposition, rule_data["enforcement"]),
            )
        )

    rules = tuple(rules_list)

    # Overlap warnings are appended after policy module is available.
    try:
        from .policy import find_overlaps
    except ImportError:
        find_overlaps = None  # type: ignore[assignment]

    if find_overlaps is not None:
        rule_index = {rule.id: index for index, rule in enumerate(rules)}
        for left_id, right_id in find_overlaps(rules):
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "rule.overlap",
                    f"/rules/{rule_index[right_id]}",
                    f"rule {right_id} overlaps {left_id}; every match will be reported",
                )
            )

    if any(item.severity == "error" for item in diagnostics):
        return ConfigValidation(None, tuple(diagnostics))

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
    return ConfigValidation(config, tuple(diagnostics))


def load_v2_config(path: str | Path, *, strict: bool = False) -> PolicyV2Config:
    result = validate_v2_config(path)
    errors = [item for item in result.diagnostics if item.severity == "error"]
    warnings = [item for item in result.diagnostics if item.severity == "warning"]
    if errors or (strict and warnings) or result.config is None:
        selected = errors if errors else warnings
        if not selected and result.config is None:
            selected = list(result.diagnostics)
        message = "\n".join(
            f"{item.code} {item.path}: {item.message}" for item in selected
        )
        raise ConfigError(message)
    return result.config

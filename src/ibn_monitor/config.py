from __future__ import annotations

import hashlib
import json
from dataclasses import MISSING, asdict, dataclass, fields, replace
from functools import lru_cache
from importlib import resources
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema

from .models import (
    Diagnostic,
    EnforcementDisposition,
    Network,
    PolicyMatch,
    PolicyProtocol,
    PolicyRule,
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
    port: int
    enabled: bool = True
    bind: str = "127.0.0.1"
    allow_non_loopback: bool = False


PROBE_PORT = 9108
OPERATIONS_PORT = 9109


@dataclass(frozen=True, slots=True)
class HttpV2Config:
    probe: ListenerV2Config = ListenerV2Config(port=PROBE_PORT)
    operations: ListenerV2Config = ListenerV2Config(port=OPERATIONS_PORT)


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


def is_loopback_host(host: str | None) -> bool:
    """True for ``localhost`` and any loopback IP literal (brackets allowed)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return bool(ip_address(host.strip("[]")).is_loopback)
    except ValueError:
        return False


@lru_cache(maxsize=1)
def _load_v2_schema() -> dict[str, Any]:
    schema_text = (
        resources.files("ibn_monitor").joinpath("policy-v2.schema.json").read_text(encoding="utf-8")
    )
    return json.loads(schema_text)


def _read_json(path: str | Path) -> Any:
    config_path = Path(path)
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {config_path}: {exc}") from exc


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
        "any" if rule.match.destination_ports is None else sorted(rule.match.destination_ports)
    )
    match: dict[str, object] = {
        "source_cidrs": sorted({str(network) for network in rule.match.source_cidrs}),
        "destination_cidrs": sorted({str(network) for network in rule.match.destination_cidrs}),
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
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
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
        "rules": [_rule_wire(rule) for rule in sorted(config.rules, key=lambda item: item.id)],
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


def _section(cls: type, raw: object, **defaults: object):
    """Build a config dataclass from a schema-validated JSON object.

    Missing keys take the dataclass default (or ``defaults``). Present values are
    coerced to the default's type so JSON integers become floats where declared.
    """
    data = {**defaults, **cast(dict[str, Any], raw or {})}
    kwargs: dict[str, object] = {}
    for field in fields(cls):
        if field.name not in data:
            continue
        value = data[field.name]
        default = defaults.get(field.name, field.default)
        if default is not MISSING and default is not None and value is not None:
            value = type(default)(value)
        kwargs[field.name] = value
    return cls(**kwargs)


def _schema_diagnostics(raw: object) -> list[Diagnostic]:
    validator = jsonschema.Draft202012Validator(_load_v2_schema())
    diagnostics: list[Diagnostic] = []
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
        diagnostics.append(
            Diagnostic("error", "schema.invalid", "/" + "/".join(parts), error.message)
        )
    return diagnostics


def _sensor(raw: dict[str, Any], diagnostics: list[Diagnostic]) -> SensorV2Config:
    topology = cast(Topology, raw["topology"])
    capture_points = tuple(
        _capture_point(cast(dict[str, Any], point), topology)
        for point in cast(list[Any], raw["capture_points"])
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
    return SensorV2Config(id=str(raw["id"]), topology=topology, capture_points=capture_points)


def _http(raw: dict[str, Any], diagnostics: list[Diagnostic]) -> HttpV2Config:
    http = HttpV2Config(
        probe=_section(ListenerV2Config, raw.get("probe"), port=PROBE_PORT),
        operations=_section(ListenerV2Config, raw.get("operations"), port=OPERATIONS_PORT),
    )
    if not is_loopback_host(http.operations.bind) and not http.operations.allow_non_loopback:
        diagnostics.append(
            Diagnostic(
                "error",
                "http.operations_non_loopback_unacknowledged",
                "/http/operations/bind",
                "non-loopback operations bind requires allow_non_loopback=true",
            )
        )
    return http


def _rule(raw: dict[str, Any], index: int, diagnostics: list[Diagnostic]) -> PolicyRule | None:
    match_raw = cast(dict[str, Any], raw["match"])
    protocol = cast(PolicyProtocol, match_raw["protocol"])
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
        return None
    return PolicyRule(
        id=str(raw["id"]),
        description=str(raw["description"]),
        enabled=bool(raw["enabled"]),
        match=PolicyMatch(
            source_cidrs=source_cidrs,
            destination_cidrs=destination_cidrs,
            protocol=protocol,
            destination_ports=destination_ports,
        ),
        severity=cast(Severity, raw["severity"]),
        enforcement=cast(EnforcementDisposition, raw["enforcement"]),
    )


def _rules(raw: list[Any], diagnostics: list[Diagnostic]) -> tuple[PolicyRule, ...]:
    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for index, rule_raw in enumerate(raw):
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
        rule = _rule(rule_data, index, diagnostics)
        if rule is not None:
            rules.append(rule)
    return tuple(rules)


def _overlap_warnings(rules: tuple[PolicyRule, ...]) -> list[Diagnostic]:
    from .policy import find_overlaps  # deferred: policy imports config types

    rule_index = {rule.id: index for index, rule in enumerate(rules)}
    return [
        Diagnostic(
            "warning",
            "rule.overlap",
            f"/rules/{rule_index[right_id]}",
            f"rule {right_id} overlaps {left_id}; every match will be reported",
        )
        for left_id, right_id in find_overlaps(rules)
    ]


def validate_v2_config(path: str | Path) -> ConfigValidation:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        return ConfigValidation(
            None, (Diagnostic("error", "schema.invalid", "/", "root must be an object"),)
        )
    diagnostics = _schema_diagnostics(raw)
    if diagnostics:
        return ConfigValidation(None, tuple(diagnostics))

    data = cast(dict[str, Any], raw)
    sensor = _sensor(cast(dict[str, Any], data["sensor"]), diagnostics)
    http = _http(cast(dict[str, Any], data.get("http", {})), diagnostics)
    rules = _rules(cast(list[Any], data["rules"]), diagnostics)
    diagnostics.extend(_overlap_warnings(rules))
    if any(item.severity == "error" for item in diagnostics):
        return ConfigValidation(None, tuple(diagnostics))

    provisional = PolicyV2Config(
        version=2,
        sensor=sensor,
        processing=_section(ProcessingV2Config, data.get("processing")),
        episodes=_section(EpisodeV2Config, data.get("episodes")),
        journal=_section(JournalV2Config, data.get("journal")),
        http=http,
        notifications=_section(NotificationV2Config, data.get("notifications")),
        rules=rules,
        policy_revision=canonical_policy_revision(rules),
        config_revision="",
    )
    config = replace(provisional, config_revision=canonical_config_revision(provisional))
    return ConfigValidation(config, tuple(diagnostics))


def load_v2_config(path: str | Path, *, strict: bool = False) -> PolicyV2Config:
    result = validate_v2_config(path)
    errors = [item for item in result.diagnostics if item.severity == "error"]
    warnings = [item for item in result.diagnostics if item.severity == "warning"]
    if errors or (strict and warnings) or result.config is None:
        selected = errors if errors else warnings
        if not selected and result.config is None:
            selected = list(result.diagnostics)
        message = "\n".join(f"{item.code} {item.path}: {item.message}" for item in selected)
        raise ConfigError(message)
    return result.config


@dataclass(frozen=True, slots=True)
class ConfigSource:
    """Produces the *effective* config: the policy file plus operator overrides.

    The same overrides apply at startup and on every SIGHUP reload, so the
    runtime identity hash stays stable while the file's non-rule fields are unchanged.
    """

    path: str | Path
    interface: str | None = None

    def load(self) -> PolicyV2Config:
        config = load_v2_config(self.path)
        if not self.interface:
            return config
        if len(config.sensor.capture_points) != 1:
            raise ConfigError(
                "--interface / IBN_CAPTURE_INTERFACE requires exactly one capture point"
            )
        point = replace(config.sensor.capture_points[0], interface=self.interface)
        overridden = replace(config, sensor=replace(config.sensor, capture_points=(point,)))
        return replace(overridden, config_revision=canonical_config_revision(overridden))

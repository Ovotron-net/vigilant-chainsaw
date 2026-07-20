from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from ipaddress import ip_network
from pathlib import Path
from typing import Any, cast

import jsonschema

from .models import Action, Protocol, Rule, Severity


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


_PROTOCOLS: frozenset[str] = frozenset({"any", "tcp", "udp", "icmp"})
_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
_ACTIONS: frozenset[str] = frozenset({"alert", "drop"})


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    schema_text = (
        resources.files("ibn_monitor").joinpath("policy.schema.json").read_text(encoding="utf-8")
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

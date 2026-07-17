from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from .models import Rule


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


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be an object")
    return value


def _integer(value: Any, path: str, *, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{path} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise ConfigError(f"{path} must be >= {minimum}{suffix}")
    return value


def _number(value: Any, path: str, *, minimum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{path} must be a number")
    result = float(value)
    if result < minimum:
        raise ConfigError(f"{path} must be >= {minimum}")
    return result


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ConfigError(f"{path} must be a non-empty string")
    return value


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path} must be an array of strings")
    return value


def _load_rule(value: Any, index: int) -> Rule:
    data = _mapping(value, f"rules[{index}]")
    rule_id = _string(data.get("id"), f"rules[{index}].id")
    description = _string(data.get("description", rule_id), f"rules[{index}].description")
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"rules[{index}].enabled must be a boolean")

    source_values = _string_list(data.get("source_cidrs", []), f"rules[{index}].source_cidrs")
    destination_values = _string_list(
        data.get("destination_cidrs", []), f"rules[{index}].destination_cidrs"
    )
    try:
        source_cidrs = tuple(ip_network(item, strict=False) for item in source_values)
        destination_cidrs = tuple(ip_network(item, strict=False) for item in destination_values)
    except ValueError as exc:
        raise ConfigError(f"rules[{index}] contains an invalid CIDR: {exc}") from exc

    protocol = _string(data.get("protocol", "any"), f"rules[{index}].protocol").lower()
    if protocol not in {"any", "tcp", "udp", "icmp"}:
        raise ConfigError(f"rules[{index}].protocol must be any, tcp, udp, or icmp")

    ports_value = data.get("destination_ports", [])
    if not isinstance(ports_value, list):
        raise ConfigError(f"rules[{index}].destination_ports must be an array")
    ports = frozenset(
        _integer(port, f"rules[{index}].destination_ports", minimum=1, maximum=65535)
        for port in ports_value
    )
    if ports and protocol not in {"tcp", "udp"}:
        raise ConfigError(
            f"rules[{index}].destination_ports requires protocol tcp or udp"
        )

    severity = _string(data.get("severity", "high"), f"rules[{index}].severity").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        raise ConfigError(f"rules[{index}].severity is invalid")

    action = _string(data.get("action", "alert"), f"rules[{index}].action").lower()
    if action not in {"alert", "drop"}:
        raise ConfigError(f"rules[{index}].action must be alert or drop")

    return Rule(
        id=rule_id,
        description=description,
        enabled=enabled,
        source_cidrs=source_cidrs,
        destination_cidrs=destination_cidrs,
        protocol=protocol,  # type: ignore[arg-type]
        destination_ports=ports,
        severity=severity,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
    )


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {config_path}: {exc}") from exc

    data = _mapping(raw, "root")
    version = _integer(data.get("version", 1), "version", minimum=1)
    if version != 1:
        raise ConfigError(f"Unsupported configuration version: {version}")

    sensor_data = _mapping(data.get("sensor", {}), "sensor")
    interface = sensor_data.get("interface")
    if interface is not None:
        interface = _string(interface, "sensor.interface")
    bpf_filter = _string(
        sensor_data.get("bpf_filter", "ip or ip6"), "sensor.bpf_filter"
    )
    promiscuous = sensor_data.get("promiscuous", False)
    if not isinstance(promiscuous, bool):
        raise ConfigError("sensor.promiscuous must be a boolean")

    logging_data = _mapping(data.get("logging", {}), "logging")
    logging_config = LoggingConfig(
        file=_string(logging_data.get("file", "events.jsonl"), "logging.file"),
        max_bytes=_integer(
            logging_data.get("max_bytes", 10_485_760), "logging.max_bytes", minimum=1024
        ),
        backup_count=_integer(
            logging_data.get("backup_count", 5), "logging.backup_count", minimum=1
        ),
    )

    health_data = _mapping(data.get("health", {}), "health")
    health_enabled = health_data.get("enabled", True)
    if not isinstance(health_enabled, bool):
        raise ConfigError("health.enabled must be a boolean")
    health_config = HealthConfig(
        enabled=health_enabled,
        bind=_string(health_data.get("bind", "127.0.0.1"), "health.bind"),
        port=_integer(health_data.get("port", 9108), "health.port", minimum=1, maximum=65535),
    )

    notification_data = _mapping(data.get("notifications", {}), "notifications")
    webhook_env = notification_data.get("webhook_url_env")
    if webhook_env is not None:
        webhook_env = _string(webhook_env, "notifications.webhook_url_env")
    minimum_severity = _string(
        notification_data.get("minimum_severity", "high"),
        "notifications.minimum_severity",
    ).lower()
    if minimum_severity not in {"low", "medium", "high", "critical"}:
        raise ConfigError("notifications.minimum_severity is invalid")
    notification_config = NotificationConfig(
        webhook_url_env=webhook_env,
        timeout_seconds=_number(
            notification_data.get("timeout_seconds", 3),
            "notifications.timeout_seconds",
            minimum=0.1,
        ),
        minimum_severity=minimum_severity,
        deduplication_seconds=_integer(
            notification_data.get("deduplication_seconds", 60),
            "notifications.deduplication_seconds",
            minimum=0,
        ),
    )

    rules_value = data.get("rules")
    if not isinstance(rules_value, list) or not rules_value:
        raise ConfigError("rules must be a non-empty array")
    rules = tuple(_load_rule(value, index) for index, value in enumerate(rules_value))
    identifiers = [rule.id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ConfigError("Rule IDs must be unique")

    return AppConfig(
        version=version,
        sensor=SensorConfig(
            interface=interface,
            bpf_filter=bpf_filter,
            promiscuous=promiscuous,
        ),
        logging=logging_config,
        health=health_config,
        notifications=notification_config,
        rules=rules,
    )

"""Shared test factories for Rule, PacketMetadata, and AppConfig."""

from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path
from typing import Any

from ibn_monitor.config import (
    AppConfig,
    HealthConfig,
    LoggingConfig,
    NotificationConfig,
    SensorConfig,
)
from ibn_monitor.models import PacketMetadata, Rule


def rule(**overrides: Any) -> Rule:
    values: dict[str, Any] = {
        "id": "DEV-DB",
        "description": "block dev database access",
        "enabled": True,
        "source_cidrs": (ip_network("10.20.0.0/16"),),
        "destination_cidrs": (ip_network("10.50.10.8/32"),),
        "protocol": "tcp",
        "destination_ports": frozenset({5432}),
        "severity": "critical",
        "action": "drop",
    }
    values.update(overrides)
    return Rule(**values)


def metadata(**overrides: Any) -> PacketMetadata:
    values: dict[str, Any] = {
        "timestamp": "now",
        "interface": "eth0",
        "source": "10.20.5.14",
        "destination": "10.50.10.8",
        "protocol": "tcp",
        "source_port": 40000,
        "destination_port": 5432,
    }
    values.update(overrides)
    return PacketMetadata(**values)


def app_config(tmp_path: Path, rules: tuple[Rule, ...]) -> AppConfig:
    return AppConfig(
        version=1,
        sensor=SensorConfig(interface=None, bpf_filter="", promiscuous=False),
        logging=LoggingConfig(file=str(tmp_path / "events.jsonl"), max_bytes=1024, backup_count=1),
        health=HealthConfig(enabled=False, bind="127.0.0.1", port=0),
        notifications=NotificationConfig(
            webhook_url_env=None,
            timeout_seconds=1.0,
            minimum_severity="low",
            deduplication_seconds=0,
        ),
        rules=rules,
    )

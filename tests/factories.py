"""Shared test factories for Rule, PacketMetadata, and AppConfig."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from ibn_monitor.config import (
    AppConfig,
    HealthConfig,
    LoggingConfig,
    NotificationConfig,
    SensorConfig,
    canonical_config_revision,
    canonical_policy_revision,
    load_v2_config,
)
from ibn_monitor.models import (
    FieldPresence,
    Observation,
    PacketMetadata,
    PolicyMatch,
    PolicyRule,
    Rule,
)


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


def v2_config(*, rules: tuple[PolicyRule, ...] | None = None):
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

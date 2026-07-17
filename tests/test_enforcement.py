from ipaddress import ip_network

from ibn_monitor.config import (
    AppConfig,
    HealthConfig,
    LoggingConfig,
    NotificationConfig,
    SensorConfig,
)
from ibn_monitor.enforcement import render_nftables
from ibn_monitor.models import Rule


def rule(**overrides):
    values = {
        "id": "DEV-DB",
        "description": "drop",
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


def test_renders_drop_rule_only():
    config = AppConfig(
        version=1,
        sensor=SensorConfig(None, "ip", False),
        logging=LoggingConfig("events.jsonl", 1024, 1),
        health=HealthConfig(False, "127.0.0.1", 9108),
        notifications=NotificationConfig(None, 3, "high", 60),
        rules=(
            rule(),
            rule(
                id="ALERT-ONLY",
                description="alert",
                source_cidrs=(),
                destination_cidrs=(),
                protocol="any",
                destination_ports=frozenset(),
                severity="low",
                action="alert",
            ),
        ),
    )
    output = render_nftables(config)
    assert "ip saddr 10.20.0.0/16 ip daddr 10.50.10.8/32 tcp dport 5432" in output
    assert "ALERT-ONLY" not in output

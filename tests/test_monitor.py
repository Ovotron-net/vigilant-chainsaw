import json
from ipaddress import ip_network

import pytest

from ibn_monitor.config import (
    AppConfig,
    HealthConfig,
    LoggingConfig,
    NotificationConfig,
    SensorConfig,
)
from ibn_monitor.models import PacketMetadata, Rule
from ibn_monitor.monitor import MonitorService


class InMemorySource:
    """Finite PacketSource adapter for tests: pushes canned metadata, then returns."""

    def __init__(self, items):
        self.items = items
        self.stopped = False

    def start(self, callback, *, on_established=None):
        if on_established is not None:
            on_established()
        for item in self.items:
            callback(item)

    def stop(self):
        self.stopped = True


class FailingSource(InMemorySource):
    def start(self, callback, *, on_established=None):
        raise OSError("capture startup failed")


def app_config(tmp_path, rules):
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


def metadata(**overrides):
    values = {
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


def rule(**overrides):
    values = {
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


def test_monitor_logs_violation_through_the_seam(tmp_path):
    config = app_config(tmp_path, (rule(),))
    source = InMemorySource([metadata(), metadata(destination_port=443), None])
    service = MonitorService(config, source)

    try:
        service.start()  # finite source: returns after delivery
    finally:
        service.stop()

    assert source.stopped
    snapshot = service.metrics.snapshot()
    assert snapshot["packets_seen"] == 3
    assert snapshot["packets_decoded"] == 2
    assert snapshot["violations"] == 1

    events = [
        json.loads(line)
        for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(events) == 1
    assert events[0]["rule"]["id"] == "DEV-DB"
    assert events[0]["network"]["destination_port"] == 5432


def test_monitor_reload_swaps_rules(tmp_path):
    config = app_config(tmp_path, (rule(),))
    service = MonitorService(config, InMemorySource([]))
    try:
        service.reload_rules(app_config(tmp_path, (rule(id="OTHER", enabled=False),)))
        assert service.engine.snapshot()[0].id == "OTHER"
    finally:
        service.stop()


def test_monitor_rolls_back_failed_startup(tmp_path):
    source = FailingSource([])
    service = MonitorService(app_config(tmp_path, (rule(),)), source)

    with pytest.raises(OSError, match="capture startup failed"):
        service.start()

    assert source.stopped
    assert service.metrics.snapshot()["ready"] is False

import json

import pytest
from factories import app_config, metadata, rule

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
        service.reload_rules((rule(id="OTHER", enabled=False),))
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

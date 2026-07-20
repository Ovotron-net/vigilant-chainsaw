import json
import time
from io import BytesIO
from ipaddress import ip_network
from unittest.mock import MagicMock

from ibn_monitor.config import LoggingConfig, NotificationConfig
from ibn_monitor.events import (
    EventLog,
    Metrics,
    NullNotifier,
    WebhookNotifier,
    build_notifier,
    create_event,
)
from ibn_monitor.models import Event, PacketMetadata, Rule


def _rule(**overrides):
    base = dict(
        id="R1",
        description="test",
        enabled=True,
        source_cidrs=(ip_network("10.0.0.0/8"),),
        destination_cidrs=(),
        protocol="tcp",
        destination_ports=frozenset({443}),
        severity="high",
        action="alert",
    )
    base.update(overrides)
    return Rule(**base)


def _packet(**overrides):
    base = dict(
        timestamp="2026-01-01T00:00:00+00:00",
        interface="eth0",
        source="10.1.2.3",
        destination="10.9.8.7",
        protocol="tcp",
        source_port=40000,
        destination_port=443,
    )
    base.update(overrides)
    return PacketMetadata(**base)


def _notification_config(**overrides):
    base = dict(
        webhook_url_env="WH",
        timeout_seconds=1.0,
        minimum_severity="high",
        deduplication_seconds=60,
    )
    base.update(overrides)
    return NotificationConfig(**base)


def _fake_urlopen_success(*_args, **_kwargs):
    response = MagicMock()
    response.status = 200
    response.headers = {}
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    response.read = MagicMock(return_value=b"")
    response.fp = BytesIO(b"")
    return response


def test_create_event_returns_frozen_event():
    event = create_event(_packet(), _rule())
    assert isinstance(event, Event)
    assert event.rule_id == "R1"
    assert event.network.destination_port == 443


def test_event_to_dict_matches_legacy_wire_shape():
    event = create_event(_packet(), _rule())
    payload = event.to_dict()
    assert payload["schema_version"] == 1
    assert payload["event_type"] == "network_policy_violation"
    assert payload["observed_at"] == "2026-01-01T00:00:00+00:00"
    assert payload["rule"] == {
        "id": "R1",
        "description": "test",
        "severity": "high",
        "action": "alert",
    }
    assert payload["network"]["source"] == "10.1.2.3"
    assert payload["network"]["destination"] == "10.9.8.7"
    assert payload["network"]["destination_port"] == 443
    assert "event_id" in payload and payload["event_id"]


def test_null_notifier_does_not_raise():
    n = NullNotifier()
    n.start()
    n.notify(create_event(_packet(), _rule()))
    n.stop()


def test_event_log_writes_jsonl_and_recent(tmp_path):
    log = EventLog(LoggingConfig(file=str(tmp_path / "e.jsonl"), max_bytes=1024, backup_count=1))
    event = create_event(_packet(), _rule())
    log.write(event)
    log.close()
    lines = (tmp_path / "e.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["rule"]["id"] == "R1"
    # recent ring survives close(); only file handlers are closed
    assert log.recent()[0]["rule"]["id"] == "R1"


def test_webhook_notifier_queue_full_increments_dropped():
    """Without a consumer, filling maxsize then one more drops and metrics."""
    metrics = Metrics()
    notifier = WebhookNotifier(_notification_config(), metrics)
    event = create_event(_packet(), _rule())
    try:
        for _ in range(1000):
            notifier.notify(event)
        assert metrics.snapshot()["notification_queue_dropped"] == 0
        notifier.notify(event)  # 1001st — queue full
        assert metrics.snapshot()["notification_queue_dropped"] == 1
    finally:
        notifier.stop()


def test_webhook_notifier_severity_gate_skips_low_events(monkeypatch):
    """Events below minimum_severity are not POSTed."""
    calls: list[object] = []

    def tracking_urlopen(*args, **kwargs):
        calls.append((args, kwargs))
        return _fake_urlopen_success(*args, **kwargs)

    monkeypatch.setenv("WH", "http://example.test/hook")
    monkeypatch.setattr("urllib.request.urlopen", tracking_urlopen)

    metrics = Metrics()
    notifier = WebhookNotifier(_notification_config(minimum_severity="high"), metrics)
    try:
        notifier.start()
        low_event = create_event(_packet(), _rule(severity="low"))
        notifier.notify(low_event)
        # Allow worker to drain the queue
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and notifier._queue.unfinished_tasks:
            time.sleep(0.05)
        time.sleep(0.1)
        assert calls == []
        assert metrics.snapshot()["notifications_sent"] == 0
        assert metrics.snapshot()["notifications_suppressed"] == 0
    finally:
        notifier.stop()


def test_webhook_notifier_dedup_suppresses_within_window(monkeypatch):
    """Second identical flow within dedup window increments notifications_suppressed."""
    calls: list[object] = []

    def tracking_urlopen(*args, **kwargs):
        calls.append((args, kwargs))
        return _fake_urlopen_success(*args, **kwargs)

    monkeypatch.setenv("WH", "http://example.test/hook")
    monkeypatch.setattr("urllib.request.urlopen", tracking_urlopen)

    metrics = Metrics()
    notifier = WebhookNotifier(
        _notification_config(minimum_severity="high", deduplication_seconds=60),
        metrics,
    )
    try:
        notifier.start()
        event = create_event(_packet(), _rule(severity="high"))
        notifier.notify(event)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and metrics.snapshot()["notifications_sent"] < 1:
            time.sleep(0.05)
        assert metrics.snapshot()["notifications_sent"] == 1

        notifier.notify(event)  # same flow key within window
        deadline = time.monotonic() + 2.0
        while (
            time.monotonic() < deadline
            and metrics.snapshot()["notifications_suppressed"] < 1
        ):
            time.sleep(0.05)
        assert metrics.snapshot()["notifications_suppressed"] == 1
        assert len(calls) == 1
    finally:
        notifier.stop()


def test_build_notifier_returns_null_when_webhook_env_unset():
    metrics = Metrics()
    notifier = build_notifier(_notification_config(webhook_url_env=None), metrics)
    assert isinstance(notifier, NullNotifier)


def test_build_notifier_returns_webhook_when_env_set():
    metrics = Metrics()
    notifier = build_notifier(_notification_config(webhook_url_env="SOME_ENV"), metrics)
    assert isinstance(notifier, WebhookNotifier)
    notifier.stop()

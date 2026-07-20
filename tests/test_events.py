import json
from ipaddress import ip_network

from ibn_monitor.config import LoggingConfig
from ibn_monitor.events import EventLog, NullNotifier, create_event
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

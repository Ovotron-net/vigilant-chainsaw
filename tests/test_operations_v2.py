import json
import time
import urllib.error
import urllib.request

import pytest
from factories import observation, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.config import ConfigSource, ListenerV2Config
from ibn_monitor.evidence import MemoryEvidenceWriter
from ibn_monitor.models import OperationalSnapshot
from ibn_monitor.monitor import LiveMonitor
from ibn_monitor.notifications_v2 import NotifierStats
from ibn_monitor.operations import OperationsServer
from ibn_monitor.probe import ProbeServer
from ibn_monitor.processing import ProcessingCounts
from ibn_monitor.read_model import ReadModel


def _snapshot(**overrides) -> OperationalSnapshot:
    values = {
        "state": "ready",
        "reasons": frozenset(),
        "ready": True,
        "policy_revision": "p",
        "config_revision": "c",
        "sources": (),
        "queue_depth": 0,
        "queue_capacity": 10,
        "app_queue_drops_total": 0,
        "kernel_drops_total": 0,
        "boot_id": "boot",
        "sensor_id": "sensor",
    }
    values.update(overrides)
    return OperationalSnapshot(**values)


def _get(url: str) -> tuple[int, dict[str, str], bytes]:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def test_read_model_publish_is_reflected_in_view_and_metrics():
    model = ReadModel(recent_maxlen=2)
    model.set_rules(v2_config().rules)
    model.publish(
        ops=_snapshot(),
        counts=ProcessingCounts(observations=3, matched_observations=1),
        journal_healthy=False,
        notifier=NotifierStats(sent=2, dropped=1),
    )

    view = model.view()
    assert view["totals"]["observations"] == 3
    assert view["journal"] == {"healthy": False}
    assert view["notifier"] == {"sent": 2, "failed": 0, "dropped": 1, "suppressed": 0}
    assert view["active_episodes"] == []
    assert view["rules"]
    text = model.metrics_text()
    assert "ibn_monitor_ready 1" in text
    assert "ibn_monitor_observations_total 3" in text
    assert "ibn_monitor_journal_healthy 0" in text
    assert "ibn_monitor_webhook_sent_total 2" in text


def test_operations_server_serves_state_dashboard_and_404():
    server = OperationsServer(ListenerV2Config(port=0), lambda: {"operational": {"ready": True}})
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        status, headers, body = _get(f"{base}/api/state")
        assert status == 200
        assert json.loads(body) == {"operational": {"ready": True}}
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

        status, headers, body = _get(f"{base}/")
        assert status == 200
        assert headers["Content-Type"].startswith("text/html")
        assert b"/api/state" in body

        status, _, body = _get(f"{base}/nope")
        assert status == 404
        assert json.loads(body) == {"error": "not_found"}
    finally:
        server.stop()
    assert server.port is None


def test_operations_server_refuses_unacknowledged_non_loopback_bind():
    server = OperationsServer(ListenerV2Config(port=0, bind="0.0.0.0"), dict)
    with pytest.raises(RuntimeError, match="non-loopback"):
        server.start()


@pytest.mark.parametrize(
    ("snapshot", "healthz", "readyz"),
    [
        (_snapshot(), 200, 200),
        (_snapshot(state="degraded", ready=False, reasons=frozenset({"kernel_drops"})), 200, 503),
        (_snapshot(state="degraded", ready=False, reasons=frozenset({"worker_dead"})), 500, 503),
    ],
    ids=["ready", "degraded", "worker-dead"],
)
def test_probe_server_health_and_readiness(snapshot, healthz, readyz):
    server = ProbeServer(
        ListenerV2Config(port=0), lambda: snapshot, metrics_provider=lambda: "m 1\n"
    )
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        assert _get(f"{base}/healthz")[0] == healthz
        status, _, body = _get(f"{base}/readyz")
        assert status == readyz
        if readyz == 503:
            assert json.loads(body)["reasons"] == sorted(snapshot.reasons)
        status, headers, body = _get(f"{base}/metrics")
        assert (status, body) == (200, b"m 1\n")
        assert headers["Content-Type"].startswith("text/plain")
    finally:
        server.stop()


def test_live_monitor_operations_state_includes_episode():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_source=ConfigSource("config/policy.v2.example.json"),
        sources=(source,),
        evidence=evidence,
        boot_id="boot-ops",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        source.push(observation(capture_point="wan", monotonic_at=time.monotonic()))
        deadline = time.time() + 2
        view: dict = {}
        while time.time() < deadline:
            view = monitor.operations_state()
            if view["totals"]["observations"] >= 1 and view["active_episodes"]:
                break
            time.sleep(0.05)
        assert view["totals"]["observations"] >= 1
        assert [item["rule_id"] for item in view["active_episodes"]] == ["DEV-DB"]
        assert view["operational"]["sensor_id"] == config.sensor.id
        assert any(r["id"] == "DEV-DB" for r in view["rules"])
        assert "ibn_monitor_observations_total 1" in monitor.metrics_text()
    finally:
        monitor.stop()

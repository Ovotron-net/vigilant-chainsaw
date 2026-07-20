import json
import urllib.request

from factories import rule

from ibn_monitor.config import HealthConfig
from ibn_monitor.events import Metrics
from ibn_monitor.health import HealthServer, _prometheus, _rule_to_dict


def test_prometheus_output_contains_counters():
    metrics = Metrics()
    metrics.mark_packet(decoded=True)
    metrics.mark_violation()
    output = _prometheus(metrics.snapshot())
    assert "ibn_monitor_packets_seen_total 1" in output
    assert "ibn_monitor_violations_total 1" in output


def test_rule_to_dict_serializes_networks_and_ports():
    payload = _rule_to_dict(rule())
    assert payload["source_cidrs"] == ["10.20.0.0/16"]
    assert payload["destination_ports"] == [5432]
    assert payload["action"] == "drop"


def test_dashboard_and_state_endpoints():
    metrics = Metrics()
    metrics.mark_violation()
    event = {"rule": {"id": "R1"}, "network": {"source": "10.0.0.1"}}
    server = HealthServer(
        HealthConfig(enabled=True, bind="127.0.0.1", port=0),
        metrics,
        rules_provider=lambda: (rule(),),
        events_provider=lambda: [event],
    )
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"

        with urllib.request.urlopen(f"{base}/") as response:
            assert response.headers["Content-Type"].startswith("text/html")
            assert b"ibn-monitor" in response.read()

        with urllib.request.urlopen(f"{base}/api/state") as response:
            state = json.loads(response.read())
        assert state["metrics"]["violations"] == 1
        assert state["rules"][0]["id"] == "DEV-DB"
        assert state["recent_events"] == [event]
    finally:
        server.stop()

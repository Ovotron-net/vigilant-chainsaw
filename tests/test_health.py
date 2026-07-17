from ibn_monitor.events import Metrics
from ibn_monitor.health import _prometheus


def test_prometheus_output_contains_counters():
    metrics = Metrics()
    metrics.mark_packet(decoded=True)
    metrics.mark_violation()
    output = _prometheus(metrics.snapshot())
    assert "ibn_monitor_packets_seen_total 1" in output
    assert "ibn_monitor_violations_total 1" in output

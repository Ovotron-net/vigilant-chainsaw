import time

from factories import observation, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.config import ConfigSource
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor


def test_live_monitor_processes_match_and_stops_cleanly():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_source=ConfigSource("config/policy.v2.example.json"),
        sources=(source,),
        evidence=evidence,
        boot_id="boot-mon",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        source.push(observation(capture_point="wan", monotonic_at=time.monotonic()))
        deadline = time.time() + 2
        while time.time() < deadline and not any(
            getattr(e.payload, "phase", None) == "start" for e in evidence.events
        ):
            time.sleep(0.05)
        assert any(getattr(e.payload, "phase", None) == "start" for e in evidence.events)
        snap = monitor.snapshot()
        assert snap.sensor_id == config.sensor.id
        assert snap.boot_id == "boot-mon"
    finally:
        monitor.stop()
    assert source.stopped


def test_live_monitor_request_reload_is_non_blocking():
    config = v2_config()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_source=ConfigSource("config/policy.v2.example.json"),
        sources=(source,),
        evidence=MemoryEvidenceWriter(),
        boot_id="boot-reload",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        monitor.request_reload()
        time.sleep(0.2)
        assert monitor.snapshot().policy_revision == config.policy_revision
    finally:
        monitor.stop()


def _reload_outcomes(evidence: MemoryEvidenceWriter) -> list[str]:
    return [
        e.payload.name
        for e in evidence.events
        if getattr(e.payload, "name", "").startswith("policy_reload_")
    ]


def test_sighup_reload_keeps_interface_override():
    """Regression: an --interface override must not turn every reload into restart_required."""
    source = ConfigSource("config/policy.v2.example.json", interface="eth9")
    config = source.load()
    assert config.sensor.capture_points[0].interface == "eth9"
    evidence = MemoryEvidenceWriter()
    monitor = LiveMonitor(
        config,
        config_source=source,
        sources=(MemoryObservationSource("wan"),),
        evidence=evidence,
        boot_id="boot-override",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        monitor.request_reload()
        deadline = time.time() + 2
        while time.time() < deadline and not _reload_outcomes(evidence):
            time.sleep(0.02)
    finally:
        monitor.stop()
    assert _reload_outcomes(evidence) == ["policy_reload_noop"]

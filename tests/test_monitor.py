import time

from factories import observation, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor


def test_live_monitor_processes_match_and_stops_cleanly():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_path="config/policy.v2.example.json",
        sources=(source,),
        evidence=evidence,
        boot_id="boot-mon",
        probe_enabled=False,
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
        config_path="config/policy.v2.example.json",
        sources=(source,),
        evidence=MemoryEvidenceWriter(),
        boot_id="boot-reload",
        probe_enabled=False,
    )
    monitor.start()
    try:
        monitor.request_reload()
        time.sleep(0.2)
        assert monitor.snapshot().policy_revision == config.policy_revision
    finally:
        monitor.stop()

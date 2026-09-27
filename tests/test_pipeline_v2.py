import time
from dataclasses import replace

from factories import observation, policy_rule, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.config import ConfigSource, runtime_identity_hash
from ibn_monitor.evidence import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor
from ibn_monitor.pipeline import ObservationQueue


def test_observation_queue_drop_oldest():
    queue = ObservationQueue(2)
    assert queue.put_drop_oldest(observation(source_port=1)) == 0
    assert queue.put_drop_oldest(observation(source_port=2)) == 0
    assert queue.put_drop_oldest(observation(source_port=3)) == 1
    first = queue.get(timeout=0.1)
    assert first is not None
    assert first.source_port == 2


def test_live_monitor_with_memory_source():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_source=ConfigSource("config/policy.v2.example.json"),
        sources=(source,),
        evidence=evidence,
        boot_id="boot-test",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        source.push(observation(capture_point="wan", monotonic_at=time.monotonic()))
        # Allow worker to process
        deadline = time.time() + 2
        while time.time() < deadline and not evidence.events:
            time.sleep(0.05)
        assert any(getattr(event.payload, "phase", None) == "start" for event in evidence.events)
    finally:
        monitor.stop()


def test_runtime_identity_ignores_rules_only():
    base = v2_config()
    changed_rules = v2_config(rules=(policy_rule(id="OTHER"),))
    assert runtime_identity_hash(base) == runtime_identity_hash(changed_rules)
    changed_episodes = replace(base, episodes=replace(base.episodes, idle_seconds=99.0))
    assert runtime_identity_hash(base) != runtime_identity_hash(changed_episodes)


def test_shutdown_closes_episodes():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_source=ConfigSource("config/policy.v2.example.json"),
        sources=(source,),
        evidence=evidence,
        boot_id="boot-stop",
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
    finally:
        monitor.stop()
    closes = [e for e in evidence.events if getattr(e.payload, "phase", None) == "close"]
    assert closes
    assert closes[-1].payload.close_reason == "shutdown"

import time
from dataclasses import replace

from factories import observation, policy_rule, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.config import runtime_identity_hash
from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor
from ibn_monitor.pipeline import ObservationQueue, process_observation
from ibn_monitor.policy import compile_policy


def test_observation_queue_drop_oldest():
    queue = ObservationQueue(2)
    assert queue.put_drop_oldest(observation(source_port=1)) == 0
    assert queue.put_drop_oldest(observation(source_port=2)) == 0
    assert queue.put_drop_oldest(observation(source_port=3)) == 1
    first = queue.get(timeout=0.1)
    assert first is not None
    assert first.source_port == 2


def test_process_observation_matches_sorted_rule_ids():
    rules = (policy_rule(id="B"), policy_rule(id="A", enforcement="none"))
    policy = compile_policy(rules, "a" * 64)
    tracker = EpisodeTracker(EpisodeSettings(10, 30, 60), id_factory=lambda: "e1")
    transitions = process_observation(
        observation(),
        lifecycle_time=0,
        policy=policy,
        tracker=tracker,
        policy_revision="a" * 64,
    )
    starts = [item for item in transitions if item.phase == "start"]
    assert [item.rule.id for item in starts] == ["A", "B"]


def test_live_monitor_with_memory_source():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_path="config/policy.v2.example.json",
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
        assert any(
            getattr(event.payload, "phase", None) == "start"
            for event in evidence.events
        )
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
        config_path="config/policy.v2.example.json",
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

"""SIGHUP reload contract (design §11): restart-only identity, revision-driven closes."""

import time
from dataclasses import replace

import pytest
from factories import observation, v2_config

from ibn_monitor import pipeline as pipeline_module
from ibn_monitor.config import PolicyV2Config
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.pipeline import PipelineConfig, PipelineWorker


def _worker(config: PolicyV2Config) -> tuple[PipelineWorker, MemoryEvidenceWriter]:
    evidence = MemoryEvidenceWriter()
    worker = PipelineWorker(
        config,
        pipeline_config=PipelineConfig(
            observation_capacity=16,
            queue_recovery_cooldown_seconds=1.0,
            graceful_drain_seconds=0.1,
            config_path="unused.json",
        ),
        evidence=evidence,
        boot_id="boot-reload",
    )
    return worker, evidence


def _open_episode(worker: PipelineWorker, evidence: MemoryEvidenceWriter) -> None:
    worker._handle_observation(observation(capture_point="wan", monotonic_at=time.monotonic()))
    assert any(getattr(e.payload, "phase", None) == "start" for e in evidence.events)


def _reload_to(
    monkeypatch: pytest.MonkeyPatch, worker: PipelineWorker, new: PolicyV2Config
) -> None:
    monkeypatch.setattr(pipeline_module, "load_v2_config", lambda _path: new)
    worker._reload()


def _system_names(evidence: MemoryEvidenceWriter) -> list[str]:
    return [e.payload.name for e in evidence.events if hasattr(e.payload, "name")]


def _close_reasons(evidence: MemoryEvidenceWriter) -> list[str]:
    return [
        e.payload.close_reason
        for e in evidence.events
        if getattr(e.payload, "phase", None) == "close"
    ]


def test_episode_setting_change_requires_restart(monkeypatch):
    base = v2_config()
    worker, evidence = _worker(base)
    _open_episode(worker, evidence)
    changed = replace(base, episodes=replace(base.episodes, idle_seconds=999.0))

    _reload_to(monkeypatch, worker, changed)

    assert _system_names(evidence)[-1] == "policy_reload_failed"
    assert evidence.events[-1].payload.fields["code"] == "restart_required"
    assert worker._tracker._settings.idle_seconds == base.episodes.idle_seconds
    assert worker._config is base
    assert _close_reasons(evidence) == []


def _rule_edits(base: PolicyV2Config):
    rule = base.rules[0]
    other_severity = "low" if rule.severity != "low" else "high"
    other_enforcement = "none" if rule.enforcement != "none" else "nftables_drop_candidate"
    return {
        "match": replace(rule, match=replace(rule.match, destination_ports=frozenset({65000}))),
        "description": replace(rule, description=rule.description + " (edited)"),
        "enabled": replace(rule, enabled=not rule.enabled),
        "severity": replace(rule, severity=other_severity),
        "enforcement": replace(rule, enforcement=other_enforcement),
    }


@pytest.mark.parametrize("edit", ["match", "description", "enabled", "severity", "enforcement"])
def test_rule_change_reloads_and_closes_episodes(monkeypatch, edit):
    base = v2_config()
    worker, evidence = _worker(base)
    _open_episode(worker, evidence)
    edited_rule = _rule_edits(base)[edit]
    new = v2_config(rules=(edited_rule, *base.rules[1:]))
    assert new.policy_revision != base.policy_revision

    _reload_to(monkeypatch, worker, new)

    assert _close_reasons(evidence) and set(_close_reasons(evidence)) == {"policy_reload"}
    assert _system_names(evidence)[-1] == "policy_reload_success"
    assert evidence.events[-1].payload.fields == {
        "old_revision": base.policy_revision,
        "new_revision": new.policy_revision,
    }
    assert worker._config is new
    assert worker._tracker.snapshot() == ()


def test_identical_config_is_noop(monkeypatch):
    base = v2_config()
    worker, evidence = _worker(base)
    _open_episode(worker, evidence)

    _reload_to(monkeypatch, worker, v2_config())

    assert _system_names(evidence)[-1] == "policy_reload_noop"
    assert _close_reasons(evidence) == []
    assert len(worker._tracker.snapshot()) >= 1

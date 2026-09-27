"""SIGHUP reload contract (design §11): restart-only identity, revision-driven closes."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from factories import observation, v2_config

from ibn_monitor.config import PolicyV2Config
from ibn_monitor.processing import EpisodeProcessor

NOW = datetime(2026, 7, 23, tzinfo=UTC)


def _processor_with_open_episode(config: PolicyV2Config) -> EpisodeProcessor:
    processor = EpisodeProcessor(config, boot_id="boot-reload")
    started = processor.observe(observation(), lifecycle_time=1.0, emitted_at=NOW)
    assert [e.payload.phase for e in started] == ["start"]
    return processor


def _reload(processor: EpisodeProcessor, new: PolicyV2Config):
    return processor.reload(new, lifecycle_time=2.0, emitted_at=NOW)


def _system_names(envelopes) -> list[str]:
    return [e.payload.name for e in envelopes if hasattr(e.payload, "name")]


def _close_reasons(envelopes) -> list[str]:
    return [
        e.payload.close_reason for e in envelopes if getattr(e.payload, "phase", None) == "close"
    ]


def test_episode_setting_change_requires_restart():
    base = v2_config()
    processor = _processor_with_open_episode(base)
    changed = replace(base, episodes=replace(base.episodes, idle_seconds=999.0))

    emitted = _reload(processor, changed)

    assert _system_names(emitted) == ["policy_reload_failed"]
    assert emitted[-1].payload.fields["code"] == "restart_required"
    assert emitted[-1].policy_revision == base.policy_revision
    assert processor.config is base
    assert len(processor.active_episodes()) == 1


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
def test_rule_change_reloads_and_closes_episodes(edit):
    base = v2_config()
    processor = _processor_with_open_episode(base)
    edited_rule = _rule_edits(base)[edit]
    new = v2_config(rules=(edited_rule, *base.rules[1:]))
    assert new.policy_revision != base.policy_revision

    emitted = _reload(processor, new)

    assert _close_reasons(emitted) == ["policy_reload"]
    assert _system_names(emitted) == ["policy_reload_success"]
    assert emitted[-1].payload.fields == {
        "old_revision": base.policy_revision,
        "new_revision": new.policy_revision,
    }
    assert emitted[-1].policy_revision == new.policy_revision
    assert processor.config is new
    assert processor.active_episodes() == ()


def test_identical_config_is_noop():
    processor = _processor_with_open_episode(v2_config())

    emitted = _reload(processor, v2_config())

    assert _system_names(emitted) == ["policy_reload_noop"]
    assert _close_reasons(emitted) == []
    assert len(processor.active_episodes()) == 1


def test_load_failure_is_sequenced_as_evidence():
    processor = _processor_with_open_episode(v2_config())

    emitted = processor.reload_failed("boom", emitted_at=NOW)

    assert _system_names(emitted) == ["policy_reload_failed"]
    assert emitted[0].payload.fields == {"detail": "boom", "code": "load_error"}
    assert emitted[0].sequence == 2

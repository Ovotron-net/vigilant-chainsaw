from dataclasses import replace

from factories import observation, policy_rule

from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.models import FieldPresence


def tracker(capacity=10):
    ids = iter(["episode-1", "episode-2", "episode-3"])
    return EpisodeTracker(
        EpisodeSettings(capacity, idle_seconds=30, progress_seconds=60),
        id_factory=lambda: next(ids),
    )


def test_start_progress_and_idle_close():
    state = tracker()
    start = state.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    assert [item.phase for item in start] == ["start"]
    state.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=40,
    )
    assert state.advance(59) == ()
    assert [item.phase for item in state.advance(60)] == ["progress"]
    assert [item.close_reason for item in state.advance(70)] == ["idle"]


def test_capture_points_merge_but_retain_per_point_counts():
    state = tracker()
    state.observe(
        policy_rule(),
        observation(capture_point="wan"),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    state.observe(
        policy_rule(),
        observation(capture_point="lan", wire_length=70),
        policy_revision="a" * 64,
        lifecycle_time=1,
    )
    close = state.close_all("source_exhausted", lifecycle_time=2)[0]
    assert close.observation_count == 2
    assert close.observed_bytes == 130
    assert close.per_capture_point == (
        ("lan", 1, 70),
        ("wan", 1, 60),
    )


def test_capacity_evicts_least_recent_episode_before_new_start():
    state = tracker(capacity=1)
    state.observe(
        policy_rule(id="R1"),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    emitted = state.observe(
        policy_rule(id="R2"),
        replace(observation(), destination_port=443),
        policy_revision="a" * 64,
        lifecycle_time=1,
    )
    assert [(item.phase, item.close_reason) for item in emitted] == [
        ("close", "capacity_evicted"),
        ("start", None),
    ]


def test_partial_keys_create_distinct_episodes():
    state = tracker()
    state.observe(
        policy_rule(),
        observation(fields=FieldPresence.complete_tcp(), decode_reason=None),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    state.observe(
        policy_rule(),
        replace(
            observation(),
            fields=FieldPresence.IP_VERSION | FieldPresence.SOURCE | FieldPresence.DESTINATION,
            decode_reason="non_initial_fragment",
            source_port=None,
            destination_port=None,
            tcp_flags=None,
            outcome="partial",
        ),
        policy_revision="a" * 64,
        lifecycle_time=1,
    )
    assert len(state.snapshot()) == 2


def test_policy_reload_closes_all():
    state = tracker()
    state.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )
    closed = state.close_all("policy_reload", lifecycle_time=1)
    assert [item.close_reason for item in closed] == ["policy_reload"]
    assert state.snapshot() == ()

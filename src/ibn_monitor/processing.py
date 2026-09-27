"""Episode processor: Observations, ticks, reloads and shutdowns in; Evidence envelopes out.

The one place that evaluates policy, tracks violation episodes, allocates
evidence sequence numbers and applies the SIGHUP reload contract. It performs
no I/O: callers (the live ``PipelineWorker`` and offline ``replay_pcap``) decide
what happens to each returned envelope, and supply every clock reading.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from itertools import count

from .config import PolicyV2Config, runtime_identity_hash
from .episodes import EpisodeSettings, EpisodeTracker
from .evidence import EvidenceSequencer
from .models import (
    EpisodeCloseReason,
    EpisodeTransition,
    EvidenceEnvelope,
    Observation,
    SystemEventName,
)
from .policy import compile_policy, evaluate_policy

Envelopes = tuple[EvidenceEnvelope, ...]


@dataclass(frozen=True, slots=True)
class ProcessingCounts:
    observations: int = 0
    complete: int = 0
    partial: int = 0
    undecodable: int = 0
    late: int = 0
    matched_observations: int = 0
    rule_matches: int = 0
    episodes_started: int = 0
    episodes_progressed: int = 0
    episodes_closed: int = 0


class _Counter:
    def __init__(self) -> None:
        self.values = {name: 0 for name in ProcessingCounts.__slots__}

    def observation(self, observation: Observation, rule_matches: int) -> None:
        values = self.values
        values["observations"] += 1
        outcome = observation.outcome if observation.outcome in {"complete", "partial"} else None
        values[outcome or "undecodable"] += 1
        if observation.late:
            values["late"] += 1
        if rule_matches:
            values["matched_observations"] += 1
            values["rule_matches"] += rule_matches

    def phase(self, transition: EpisodeTransition) -> None:
        name = {"start": "started", "progress": "progressed", "close": "closed"}[transition.phase]
        self.values[f"episodes_{name}"] += 1

    def freeze(self) -> ProcessingCounts:
        return ProcessingCounts(**self.values)


class EpisodeProcessor:
    """Deterministic, single-threaded evidence producer for one sensor boot."""

    def __init__(self, config: PolicyV2Config, *, boot_id: str) -> None:
        self._config = config
        self._policy = compile_policy(config.rules, config.policy_revision)
        self._runtime_hash = runtime_identity_hash(config)
        episode_ids = count(1)
        self._tracker = EpisodeTracker(
            EpisodeSettings(
                config.episodes.capacity,
                config.episodes.idle_seconds,
                config.episodes.progress_seconds,
            ),
            id_factory=lambda: f"{boot_id}:episode:{next(episode_ids)}",
        )
        self._sequencer = EvidenceSequencer(config.sensor.id, boot_id)
        self._counter = _Counter()

    @property
    def config(self) -> PolicyV2Config:
        """The effective config; replaced only by a successful ``reload``."""
        return self._config

    def observe(
        self,
        observation: Observation,
        *,
        lifecycle_time: float,
        emitted_at: datetime,
    ) -> Envelopes:
        """Advance episode timers to ``lifecycle_time``, then match one Observation."""
        transitions = list(self._tracker.advance(lifecycle_time))
        matches = evaluate_policy(self._policy, observation)
        self._counter.observation(observation, len(matches))
        for match in sorted(matches, key=lambda item: item.rule.id):
            transitions.extend(
                self._tracker.observe(
                    match.rule,
                    observation,
                    policy_revision=self._config.policy_revision,
                    lifecycle_time=lifecycle_time,
                )
            )
        return self._wrap(transitions, emitted_at)

    def tick(self, *, lifecycle_time: float, emitted_at: datetime) -> Envelopes:
        """Emit idle closes and progress transitions due at ``lifecycle_time``."""
        return self._wrap(self._tracker.advance(lifecycle_time), emitted_at)

    def close_all(
        self,
        reason: EpisodeCloseReason,
        *,
        lifecycle_time: float,
        emitted_at: datetime,
    ) -> Envelopes:
        return self._wrap(
            self._tracker.close_all(reason, lifecycle_time=lifecycle_time), emitted_at
        )

    def reload(
        self,
        new_config: PolicyV2Config,
        *,
        lifecycle_time: float,
        emitted_at: datetime,
    ) -> Envelopes:
        """Apply the SIGHUP contract: restart-only gate, revision no-op, or close-and-swap."""
        if runtime_identity_hash(new_config) != self._runtime_hash:
            return self.system(
                "policy_reload_failed",
                {"detail": "restart_required", "code": "restart_required"},
                emitted_at=emitted_at,
            )
        if new_config.policy_revision == self._config.policy_revision:
            return self.system(
                "policy_reload_noop",
                {"policy_revision": new_config.policy_revision},
                emitted_at=emitted_at,
            )
        old_revision = self._config.policy_revision
        closed = self.close_all(
            "policy_reload", lifecycle_time=lifecycle_time, emitted_at=emitted_at
        )
        self._config = new_config
        self._policy = compile_policy(new_config.rules, new_config.policy_revision)
        return closed + self.system(
            "policy_reload_success",
            {"old_revision": old_revision, "new_revision": new_config.policy_revision},
            emitted_at=emitted_at,
        )

    def reload_failed(self, detail: str, *, emitted_at: datetime) -> Envelopes:
        """Record a reload whose config could not be loaded at all."""
        return self.system(
            "policy_reload_failed",
            {"detail": detail, "code": "load_error"},
            emitted_at=emitted_at,
        )

    def system(
        self,
        name: SystemEventName,
        fields: dict[str, object],
        *,
        emitted_at: datetime,
    ) -> Envelopes:
        """Sequence one system event; ``None`` fields are dropped."""
        cleaned = {key: value for key, value in fields.items() if value is not None}
        return (
            self._sequencer.wrap_system(
                name,
                cleaned,
                emitted_at=emitted_at,
                policy_revision=self._config.policy_revision,
            ),
        )

    def counts(self) -> ProcessingCounts:
        return self._counter.freeze()

    def active_episodes(self) -> tuple[EpisodeTransition, ...]:
        return self._tracker.snapshot()

    def _wrap(self, transitions, emitted_at: datetime) -> Envelopes:
        envelopes = []
        for transition in transitions:
            self._counter.phase(transition)
            envelopes.append(self._sequencer.wrap_episode(transition, emitted_at=emitted_at))
        return tuple(envelopes)

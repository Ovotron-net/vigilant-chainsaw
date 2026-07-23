from __future__ import annotations

import heapq
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from typing import TextIO

from .config import PolicyV2Config
from .decode import ObservationContext
from .episodes import EpisodeSettings, EpisodeTracker
from .events import EvidenceSequencer, serialize_evidence
from .models import Observation
from .pcap import iter_pcap_observations
from .pipeline import process_observation
from .policy import compile_policy


@dataclass(frozen=True, slots=True)
class ReplaySummary:
    observations: int
    complete_observations: int
    partial_observations: int
    undecodable_observations: int
    late_observations: int
    matched_observations: int
    rule_matches: int
    episodes_started: int
    episodes_progressed: int
    episodes_closed: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class _Counters:
    def __init__(self) -> None:
        self.observations = 0
        self.complete_observations = 0
        self.partial_observations = 0
        self.undecodable_observations = 0
        self.late_observations = 0
        self.matched_observations = 0
        self.rule_matches = 0
        self.episodes_started = 0
        self.episodes_progressed = 0
        self.episodes_closed = 0

    def record_outcome(self, observation: Observation) -> None:
        self.observations += 1
        if observation.outcome == "complete":
            self.complete_observations += 1
        elif observation.outcome == "partial":
            self.partial_observations += 1
        else:
            self.undecodable_observations += 1
        if observation.late:
            self.late_observations += 1

    def record_phase(self, phase: str) -> None:
        if phase == "start":
            self.episodes_started += 1
        elif phase == "progress":
            self.episodes_progressed += 1
        elif phase == "close":
            self.episodes_closed += 1

    def freeze(self) -> ReplaySummary:
        return ReplaySummary(
            observations=self.observations,
            complete_observations=self.complete_observations,
            partial_observations=self.partial_observations,
            undecodable_observations=self.undecodable_observations,
            late_observations=self.late_observations,
            matched_observations=self.matched_observations,
            rule_matches=self.rule_matches,
            episodes_started=self.episodes_started,
            episodes_progressed=self.episodes_progressed,
            episodes_closed=self.episodes_closed,
        )


def _epoch(observation: Observation) -> float:
    return observation.captured_at.timestamp()


def _write_transitions(transitions, sequencer, output, counters) -> None:
    for transition in transitions:
        event = sequencer.wrap_episode(
            transition,
            emitted_at=datetime.fromtimestamp(transition.lifecycle_time, UTC),
        )
        output.write(serialize_evidence(event) + "\n")
        counters.record_phase(transition.phase)


def _process_observation(
    observation: Observation,
    lifecycle_time: float,
    *,
    policy,
    tracker: EpisodeTracker,
    sequencer: EvidenceSequencer,
    output: TextIO,
    counters: _Counters,
    policy_revision: str,
) -> None:
    from .policy import evaluate_policy

    matches = evaluate_policy(policy, observation)
    if matches:
        counters.matched_observations += 1
        counters.rule_matches += len(matches)
    transitions = process_observation(
        observation,
        lifecycle_time=lifecycle_time,
        policy=policy,
        tracker=tracker,
        policy_revision=policy_revision,
    )
    _write_transitions(transitions, sequencer, output, counters)


def replay_pcap(
    config: PolicyV2Config,
    pcap_path: str | Path,
    output: TextIO,
    *,
    boot_id: str,
) -> ReplaySummary:
    policy = compile_policy(config.rules, config.policy_revision)
    episode_sequence = count(1)
    tracker = EpisodeTracker(
        EpisodeSettings(
            config.episodes.capacity,
            config.episodes.idle_seconds,
            config.episodes.progress_seconds,
        ),
        id_factory=lambda: f"{boot_id}:episode:{next(episode_sequence)}",
    )
    sequencer = EvidenceSequencer(config.sensor.id, boot_id)
    counters = _Counters()
    heap: list[tuple[float, int, Observation]] = []
    max_seen = float("-inf")
    finalized_watermark = float("-inf")
    ordinal = 0
    last_lifecycle = float("-inf")
    lateness = config.episodes.replay_lateness_seconds

    context = ObservationContext(
        captured_at=datetime.fromtimestamp(0, UTC),
        monotonic_at=None,
        sensor_id=config.sensor.id,
        source_generation=f"replay:{boot_id}",
        capture_point="pcap",
        interface=None,
        direction="unknown",
    )

    def drain_ready(watermark: float) -> None:
        nonlocal last_lifecycle
        while heap and heap[0][0] <= watermark:
            event_time, _order, observation = heapq.heappop(heap)
            lifecycle_time = max(last_lifecycle, event_time)
            last_lifecycle = lifecycle_time
            _process_observation(
                observation,
                lifecycle_time,
                policy=policy,
                tracker=tracker,
                sequencer=sequencer,
                output=output,
                counters=counters,
                policy_revision=config.policy_revision,
            )

    for observation in iter_pcap_observations(pcap_path, context=context):
        event_time = _epoch(observation)
        if event_time < finalized_watermark:
            observation = replace(observation, late=True)
            counters.record_outcome(observation)
            lifecycle_time = max(last_lifecycle, finalized_watermark)
            last_lifecycle = lifecycle_time
            _process_observation(
                observation,
                lifecycle_time,
                policy=policy,
                tracker=tracker,
                sequencer=sequencer,
                output=output,
                counters=counters,
                policy_revision=config.policy_revision,
            )
            continue

        counters.record_outcome(observation)
        heapq.heappush(heap, (event_time, ordinal, observation))
        ordinal += 1
        max_seen = max(max_seen, event_time)
        watermark = max_seen - lateness
        drain_ready(watermark)
        finalized_watermark = max(finalized_watermark, watermark)

    if counters.observations == 0:
        return counters.freeze()

    # Drain remaining observations in timestamp order.
    remaining = sorted(heap, key=lambda item: (item[0], item[1]))
    heap.clear()
    for event_time, _order, observation in remaining:
        lifecycle_time = max(last_lifecycle, event_time)
        last_lifecycle = lifecycle_time
        _process_observation(
            observation,
            lifecycle_time,
            policy=policy,
            tracker=tracker,
            sequencer=sequencer,
            output=output,
            counters=counters,
            policy_revision=config.policy_revision,
        )

    closed = tracker.close_all(
        "source_exhausted",
        lifecycle_time=max(last_lifecycle, 0.0),
    )
    _write_transitions(closed, sequencer, output, counters)
    return counters.freeze()

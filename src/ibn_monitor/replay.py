from __future__ import annotations

import heapq
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from .config import PolicyV2Config
from .decode import ObservationContext
from .evidence import serialize_evidence
from .models import Observation
from .pcap import iter_pcap_observations
from .processing import EpisodeProcessor


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


def _summary(processor: EpisodeProcessor) -> ReplaySummary:
    counts = processor.counts()
    return ReplaySummary(
        observations=counts.observations,
        complete_observations=counts.complete,
        partial_observations=counts.partial,
        undecodable_observations=counts.undecodable,
        late_observations=counts.late,
        matched_observations=counts.matched_observations,
        rule_matches=counts.rule_matches,
        episodes_started=counts.episodes_started,
        episodes_progressed=counts.episodes_progressed,
        episodes_closed=counts.episodes_closed,
    )


def _epoch(observation: Observation) -> float:
    return observation.captured_at.timestamp()


def _emitted_at(lifecycle_time: float) -> datetime:
    """Replay stamps evidence with event time so output is byte-deterministic."""
    return datetime.fromtimestamp(lifecycle_time, UTC)


def replay_pcap(
    config: PolicyV2Config,
    pcap_path: str | Path,
    output: TextIO,
    *,
    boot_id: str,
) -> ReplaySummary:
    processor = EpisodeProcessor(config, boot_id=boot_id)
    seen = 0

    def emit(envelopes) -> None:
        for envelope in envelopes:
            output.write(serialize_evidence(envelope) + "\n")

    def process(observation: Observation, lifecycle_time: float) -> None:
        emit(
            processor.observe(
                observation,
                lifecycle_time=lifecycle_time,
                emitted_at=_emitted_at(lifecycle_time),
            )
        )

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
            last_lifecycle = max(last_lifecycle, event_time)
            process(observation, last_lifecycle)

    for observation in iter_pcap_observations(pcap_path, context=context):
        seen += 1
        event_time = _epoch(observation)
        if event_time < finalized_watermark:
            last_lifecycle = max(last_lifecycle, finalized_watermark)
            process(replace(observation, late=True), last_lifecycle)
            continue

        heapq.heappush(heap, (event_time, ordinal, observation))
        ordinal += 1
        max_seen = max(max_seen, event_time)
        watermark = max_seen - lateness
        drain_ready(watermark)
        finalized_watermark = max(finalized_watermark, watermark)

    if seen == 0:
        return _summary(processor)

    # Drain remaining observations in timestamp order.
    for event_time, _order, observation in sorted(heap, key=lambda item: (item[0], item[1])):
        last_lifecycle = max(last_lifecycle, event_time)
        process(observation, last_lifecycle)
    heap.clear()

    end = max(last_lifecycle, 0.0)
    emit(processor.close_all("source_exhausted", lifecycle_time=end, emitted_at=_emitted_at(end)))
    return _summary(processor)

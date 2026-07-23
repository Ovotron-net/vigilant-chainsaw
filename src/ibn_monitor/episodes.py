from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from .models import (
    EpisodeCloseReason,
    EpisodeKey,
    EpisodeTransition,
    Observation,
    PolicyRule,
)


@dataclass(frozen=True, slots=True)
class EpisodeSettings:
    capacity: int
    idle_seconds: float
    progress_seconds: float


class _EpisodeState:
    def __init__(
        self,
        episode_id: str,
        key: EpisodeKey,
        rule: PolicyRule,
        observation: Observation,
        lifecycle_time: float,
    ) -> None:
        self.episode_id = episode_id
        self.key = key
        self.rule = rule
        self.first_observed_at = observation.captured_at
        self.last_observed_at = observation.captured_at
        self.last_lifecycle_time = lifecycle_time
        self.last_progress_time = lifecycle_time
        self.observation_count = 1
        self.observed_bytes = observation.wire_length
        self.late_observation_count = int(observation.late)
        self.per_point: dict[str, list[int]] = {
            observation.capture_point: [1, observation.wire_length]
        }

    def update(self, observation: Observation, lifecycle_time: float) -> None:
        self.observation_count += 1
        self.observed_bytes += observation.wire_length
        self.late_observation_count += int(observation.late)
        point = self.per_point.setdefault(observation.capture_point, [0, 0])
        point[0] += 1
        point[1] += observation.wire_length
        if not observation.late:
            if observation.captured_at < self.first_observed_at:
                self.first_observed_at = observation.captured_at
            if observation.captured_at > self.last_observed_at:
                self.last_observed_at = observation.captured_at
        self.last_lifecycle_time = max(self.last_lifecycle_time, lifecycle_time)

    def transition(
        self,
        phase: str,
        lifecycle_time: float,
        *,
        truncated: bool = False,
        close_reason: EpisodeCloseReason | None = None,
    ) -> EpisodeTransition:
        return EpisodeTransition(
            episode_id=self.episode_id,
            phase=phase,  # type: ignore[arg-type]
            key=self.key,
            rule=self.rule,
            first_observed_at=self.first_observed_at,
            last_observed_at=self.last_observed_at,
            lifecycle_time=lifecycle_time,
            observation_count=self.observation_count,
            observed_bytes=self.observed_bytes,
            late_observation_count=self.late_observation_count,
            per_capture_point=tuple(
                (name, counts[0], counts[1])
                for name, counts in sorted(self.per_point.items())
            ),
            truncated=truncated,
            close_reason=close_reason,
        )


def episode_key(
    rule: PolicyRule,
    observation: Observation,
    *,
    policy_revision: str,
) -> EpisodeKey:
    return EpisodeKey(
        policy_revision=policy_revision,
        rule_id=rule.id,
        ip_version=observation.ip_version,
        source=observation.source,
        destination=observation.destination,
        protocol=observation.protocol,
        source_port=observation.source_port,
        destination_port=observation.destination_port,
        icmp_type=observation.icmp_type,
        icmp_code=observation.icmp_code,
        fields=int(observation.fields),
        decode_reason=observation.decode_reason,
    )


class EpisodeTracker:
    def __init__(
        self,
        settings: EpisodeSettings,
        *,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._settings = settings
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._states: OrderedDict[EpisodeKey, _EpisodeState] = OrderedDict()

    def observe(
        self,
        rule: PolicyRule,
        observation: Observation,
        *,
        policy_revision: str,
        lifecycle_time: float,
    ) -> tuple[EpisodeTransition, ...]:
        key = episode_key(rule, observation, policy_revision=policy_revision)
        emitted: list[EpisodeTransition] = []
        existing = self._states.get(key)
        if existing is not None:
            existing.update(observation, lifecycle_time)
            self._states.move_to_end(key)
            return ()

        if len(self._states) >= self._settings.capacity:
            _, victim = self._states.popitem(last=False)
            emitted.append(
                victim.transition(
                    "close",
                    lifecycle_time,
                    truncated=True,
                    close_reason="capacity_evicted",
                )
            )

        state = _EpisodeState(
            self._id_factory(),
            key,
            rule,
            observation,
            lifecycle_time,
        )
        self._states[key] = state
        emitted.append(state.transition("start", lifecycle_time))
        return tuple(emitted)

    def advance(self, now: float) -> tuple[EpisodeTransition, ...]:
        emitted: list[EpisodeTransition] = []
        to_close: list[EpisodeKey] = []
        for key, state in list(self._states.items()):
            idle_age = now - state.last_lifecycle_time
            if idle_age >= self._settings.idle_seconds:
                emitted.append(
                    state.transition("close", now, close_reason="idle")
                )
                to_close.append(key)
                continue
            if now - state.last_progress_time >= self._settings.progress_seconds:
                emitted.append(state.transition("progress", now))
                state.last_progress_time = now
        for key in to_close:
            self._states.pop(key, None)
        return tuple(emitted)

    def close_all(
        self,
        reason: EpisodeCloseReason,
        *,
        lifecycle_time: float,
    ) -> tuple[EpisodeTransition, ...]:
        emitted = tuple(
            state.transition("close", lifecycle_time, close_reason=reason)
            for state in self._states.values()
        )
        self._states.clear()
        return emitted

    def snapshot(self) -> tuple[EpisodeTransition, ...]:
        return tuple(
            state.transition("progress", state.last_lifecycle_time)
            for state in self._states.values()
        )

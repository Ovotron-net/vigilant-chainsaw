from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .config import PolicyV2Config, load_v2_config, runtime_identity_hash
from .episodes import EpisodeSettings, EpisodeTracker
from .events import EvidenceSequencer
from .evidence_stub import EvidenceWriter
from .models import (
    ControlMessage,
    EpisodeTransition,
    Observation,
    OperationalSnapshot,
)
from .notifications_v2 import NullV2Notifier, V2Notifier
from .ops_state import OperationalStateMachine
from .policy import CompiledPolicy, compile_policy, evaluate_policy

logger = logging.getLogger(__name__)

CONTROL_LANE_CAPACITY = 256
OBSERVATION_BATCH = 64


class ObservationQueue:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._items: deque[Observation] = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)

    def put_drop_oldest(self, item: Observation) -> int:
        evicted = 0
        with self._not_empty:
            while len(self._items) >= self._capacity:
                self._items.popleft()
                evicted += 1
            self._items.append(item)
            self._not_empty.notify()
        return evicted

    def get(self, timeout: float | None = None) -> Observation | None:
        with self._not_empty:
            if not self._items:
                if timeout is None:
                    return None
                self._not_empty.wait(timeout)
            if not self._items:
                return None
            return self._items.popleft()

    def qsize(self) -> int:
        with self._lock:
            return len(self._items)

    def drain(self, max_items: int | None = None) -> list[Observation]:
        with self._lock:
            if max_items is None:
                items = list(self._items)
                self._items.clear()
                return items
            result: list[Observation] = []
            while self._items and len(result) < max_items:
                result.append(self._items.popleft())
            return result


class ControlLane:
    def __init__(self, capacity: int = CONTROL_LANE_CAPACITY) -> None:
        self._capacity = capacity
        self._items: deque[ControlMessage] = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._shutdown: ControlMessage | None = None
        self._force: ControlMessage | None = None
        self._reload_pending: ControlMessage | None = None
        self._latest_timer: ControlMessage | None = None
        self._latest_stats: dict[str, ControlMessage] = {}
        self._latest_lifecycle: dict[str, ControlMessage] = {}
        self._dropped_sum: dict[str, ControlMessage] = {}
        self.drops_total = 0

    def put(self, message: ControlMessage) -> None:
        with self._not_empty:
            if message.kind == "force_shutdown":
                self._force = message
                self._shutdown = None
            elif message.kind == "shutdown":
                if self._force is None:
                    self._shutdown = message
            elif message.kind == "reload_request":
                self._reload_pending = message
            elif message.kind == "timer":
                self._latest_timer = message
            elif message.kind == "source_stats" and message.capture_point:
                self._latest_stats[message.capture_point] = message
            elif message.kind == "observation_dropped" and message.capture_point:
                existing = self._dropped_sum.get(message.capture_point)
                drops = message.drops + (existing.drops if existing else 0)
                self._dropped_sum[message.capture_point] = ControlMessage(
                    kind="observation_dropped",
                    monotonic_at=message.monotonic_at,
                    capture_point=message.capture_point,
                    drops=drops,
                )
            elif message.capture_point and message.kind.startswith("source_"):
                self._latest_lifecycle[message.capture_point] = message
            else:
                self._items.append(message)
            self._not_empty.notify()

    def drain(self) -> list[ControlMessage]:
        with self._lock:
            messages: list[ControlMessage] = []
            if self._force is not None:
                messages.append(self._force)
                self._force = None
                self._shutdown = None
            elif self._shutdown is not None:
                messages.append(self._shutdown)
                self._shutdown = None
            if self._reload_pending is not None:
                messages.append(self._reload_pending)
                self._reload_pending = None
            if self._latest_timer is not None:
                messages.append(self._latest_timer)
                self._latest_timer = None
            messages.extend(self._latest_stats.values())
            self._latest_stats.clear()
            messages.extend(self._dropped_sum.values())
            self._dropped_sum.clear()
            messages.extend(self._latest_lifecycle.values())
            self._latest_lifecycle.clear()
            while self._items:
                messages.append(self._items.popleft())
            return messages

    def wait(self, timeout: float) -> None:
        with self._not_empty:
            self._not_empty.wait(timeout)


def process_observation(
    observation: Observation,
    *,
    lifecycle_time: float,
    policy: CompiledPolicy,
    tracker: EpisodeTracker,
    policy_revision: str,
) -> tuple[EpisodeTransition, ...]:
    transitions: list[EpisodeTransition] = list(tracker.advance(lifecycle_time))
    matches = evaluate_policy(policy, observation)
    for match in sorted(matches, key=lambda item: item.rule.id):
        transitions.extend(
            tracker.observe(
                match.rule,
                observation,
                policy_revision=policy_revision,
                lifecycle_time=lifecycle_time,
            )
        )
    return tuple(transitions)


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    observation_capacity: int
    queue_recovery_cooldown_seconds: float
    graceful_drain_seconds: float
    timer_interval_seconds: float = 0.25
    config_path: str = ""


class PipelineWorker:
    def __init__(
        self,
        config: PolicyV2Config,
        *,
        pipeline_config: PipelineConfig,
        evidence: EvidenceWriter,
        boot_id: str,
        clock: Any | None = None,
        notifier: V2Notifier | None = None,
    ) -> None:
        self._config = config
        self._pipeline_config = pipeline_config
        self._evidence = evidence
        self._notifier: V2Notifier = notifier or NullV2Notifier()
        self._boot_id = boot_id
        self._clock = clock or time
        self._policy = compile_policy(config.rules, config.policy_revision)
        self._runtime_hash = runtime_identity_hash(config)
        episode_ids = iter(range(1, 10**9))
        self._tracker = EpisodeTracker(
            EpisodeSettings(
                config.episodes.capacity,
                config.episodes.idle_seconds,
                config.episodes.progress_seconds,
            ),
            id_factory=lambda: f"{boot_id}:episode:{next(episode_ids)}",
        )
        self._sequencer = EvidenceSequencer(config.sensor.id, boot_id)
        self._observations = ObservationQueue(pipeline_config.observation_capacity)
        self._control = ControlLane()
        self._ops = OperationalStateMachine(
            sensor_id=config.sensor.id,
            boot_id=boot_id,
            queue_capacity=pipeline_config.observation_capacity,
            sources=tuple(
                (point.name, point.interface) for point in config.sensor.capture_points
            ),
        )
        self._ops.set_policy(config.policy_revision, config.config_revision)
        self._snapshot = self._ops.snapshot()
        self._snapshot_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._force = False
        self._app_drop_incident_start: float | None = None
        self._kernel_drop_incident_start: float | None = None
        self._last_app_drop_mono = 0.0
        self._last_kernel_drop_mono = 0.0
        self._timer_thread: threading.Thread | None = None

    def observation_sink(self, observation: Observation) -> None:
        evicted = self._observations.put_drop_oldest(observation)
        if evicted:
            self._control.put(
                ControlMessage(
                    kind="observation_dropped",
                    monotonic_at=self._clock.monotonic(),
                    capture_point=observation.capture_point,
                    drops=evicted,
                )
            )

    def control_sink(self, message: ControlMessage) -> None:
        self._control.put(message)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="ibn-pipeline", daemon=True)
        self._thread.start()
        self._timer_thread = threading.Thread(
            target=self._timer_loop, name="ibn-pipeline-timer", daemon=True
        )
        self._timer_thread.start()

    def stop(self, *, force: bool = False) -> None:
        self._force = force
        self._control.put(
            ControlMessage(
                kind="force_shutdown" if force else "shutdown",
                monotonic_at=self._clock.monotonic(),
            )
        )
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._pipeline_config.graceful_drain_seconds + 2)
        if self._timer_thread is not None:
            self._timer_thread.join(timeout=1)

    def snapshot(self) -> OperationalSnapshot:
        with self._snapshot_lock:
            return self._snapshot

    def _publish(self) -> None:
        self._ops.set_queue_depth(self._observations.qsize())
        snap = self._ops.snapshot()
        with self._snapshot_lock:
            self._snapshot = snap

    def _timer_loop(self) -> None:
        while not self._stop.is_set():
            self._control.put(
                ControlMessage(kind="timer", monotonic_at=self._clock.monotonic())
            )
            self._stop.wait(self._pipeline_config.timer_interval_seconds)

    def _run(self) -> None:
        try:
            while True:
                for message in self._control.drain():
                    self._handle_control(message)
                    if message.kind == "force_shutdown" or (
                        message.kind == "shutdown" and self._force
                    ):
                        self._shutdown(force=True)
                        return
                    if message.kind == "shutdown":
                        self._shutdown(force=False)
                        return
                for _ in range(OBSERVATION_BATCH):
                    obs = self._observations.get(timeout=0.0)
                    if obs is None:
                        break
                    self._handle_observation(obs)
                else:
                    # Processed a full batch; immediately continue.
                    continue
                if self._stop.is_set() and self._observations.qsize() == 0:
                    # Stop requested without an explicit shutdown control: still close cleanly.
                    self._shutdown(force=self._force)
                    return
                self._control.wait(self._pipeline_config.timer_interval_seconds)
        except Exception:
            logger.exception("pipeline worker crashed")
            self._ops.mark_worker_dead()
            self._publish()
            raise

    def _handle_observation(self, observation: Observation) -> None:
        lifecycle = (
            observation.monotonic_at
            if observation.monotonic_at is not None
            else self._clock.monotonic()
        )
        transitions = process_observation(
            observation,
            lifecycle_time=lifecycle,
            policy=self._policy,
            tracker=self._tracker,
            policy_revision=self._config.policy_revision,
        )
        now = datetime.now(UTC)
        for transition in transitions:
            envelope = self._sequencer.wrap_episode(transition, emitted_at=now)
            self._evidence.commit(envelope)
            self._notifier.notify(envelope)
        self._publish()

    def _handle_control(self, message: ControlMessage) -> None:
        if message.kind == "timer":
            now = message.monotonic_at
            for transition in self._tracker.advance(now):
                envelope = self._sequencer.wrap_episode(
                    transition, emitted_at=datetime.now(UTC)
                )
                self._evidence.commit(envelope)
                self._notifier.notify(envelope)
            self._maybe_clear_drop_reasons(now)
            self._publish()
            return
        if message.kind == "reload_request":
            self._reload()
            return
        if message.kind == "observation_dropped":
            self._ops.note_app_drops(message.drops)
            self._last_app_drop_mono = message.monotonic_at
            if self._app_drop_incident_start is None:
                self._app_drop_incident_start = message.monotonic_at
            self._publish()
            return
        if message.kind == "source_stats" and message.stats is not None:
            delta = self._ops.note_kernel_drops(
                message.stats.capture_point, message.stats.kernel_drops
            )
            if delta:
                self._last_kernel_drop_mono = message.monotonic_at
                if self._kernel_drop_incident_start is None:
                    self._kernel_drop_incident_start = message.monotonic_at
                    self._commit_system(
                        "kernel_drops_observed",
                        {
                            "capture_point": message.stats.capture_point,
                            "source_generation": message.stats.source_generation,
                            "delta": delta,
                            "total": message.stats.kernel_drops,
                        },
                    )
            self._ops.set_source(
                message.stats.capture_point,
                state="established",
                source_generation=message.stats.source_generation,
                kernel_packets=message.stats.kernel_packets,
                kernel_drops=message.stats.kernel_drops,
            )
            self._publish()
            return
        if message.kind in {
            "source_established",
            "source_recovered",
            "source_failed",
            "source_retrying",
            "source_stopped",
        }:
            state_map = {
                "source_established": "established",
                "source_recovered": "established",
                "source_failed": "failed",
                "source_retrying": "retrying",
                "source_stopped": "stopped",
            }
            assert message.capture_point is not None
            self._ops.set_source(
                message.capture_point,
                state=state_map[message.kind],  # type: ignore[arg-type]
                source_generation=message.source_generation,
                last_error=message.detail,
            )
            self._commit_system(
                message.kind,  # type: ignore[arg-type]
                {
                    "capture_point": message.capture_point,
                    "source_generation": message.source_generation,
                    "detail": message.detail,
                },
            )
            self._publish()

    def _maybe_clear_drop_reasons(self, now: float) -> None:
        cooldown = self._pipeline_config.queue_recovery_cooldown_seconds
        depth = self._observations.qsize()
        capacity = self._pipeline_config.observation_capacity
        reasons = self._ops.snapshot().reasons
        if (
            "app_queue_drops" in reasons
            and depth < capacity * 0.5
            and (now - self._last_app_drop_mono) >= cooldown
        ):
            self._ops.clear_app_drops()
            self._commit_system(
                "coverage_gap",
                {
                    "cause": "app_queue_drops",
                    "drops": self._ops.snapshot().app_queue_drops_total,
                    "interval_start": self._app_drop_incident_start,
                    "interval_end": now,
                },
            )
            self._app_drop_incident_start = None
        if "kernel_drops" in reasons and (now - self._last_kernel_drop_mono) >= cooldown:
            self._ops.clear_kernel_drops()
            self._commit_system(
                "coverage_gap",
                {
                    "cause": "kernel_drops",
                    "drops": self._ops.snapshot().kernel_drops_total,
                    "interval_start": self._kernel_drop_incident_start,
                    "interval_end": now,
                },
            )
            self._kernel_drop_incident_start = None

    def _reload(self) -> None:
        path = self._pipeline_config.config_path
        try:
            new_config = load_v2_config(path)
        except Exception as exc:
            self._commit_system(
                "policy_reload_failed",
                {"detail": str(exc), "code": "load_error"},
                policy_revision=self._config.policy_revision,
            )
            return
        new_hash = runtime_identity_hash(new_config)
        if new_hash != self._runtime_hash:
            self._commit_system(
                "policy_reload_failed",
                {"detail": "restart_required", "code": "restart_required"},
                policy_revision=self._config.policy_revision,
            )
            return
        if new_config.policy_revision == self._config.policy_revision:
            self._commit_system(
                "policy_reload_noop",
                {"policy_revision": new_config.policy_revision},
                policy_revision=new_config.policy_revision,
            )
            return
        old_rev = self._config.policy_revision
        now = self._clock.monotonic()
        for transition in self._tracker.close_all("policy_reload", lifecycle_time=now):
            envelope = self._sequencer.wrap_episode(
                transition, emitted_at=datetime.now(UTC)
            )
            self._evidence.commit(envelope)
            self._notifier.notify(envelope)
        self._config = new_config
        self._policy = compile_policy(new_config.rules, new_config.policy_revision)
        self._ops.set_policy(new_config.policy_revision, new_config.config_revision)
        self._commit_system(
            "policy_reload_success",
            {"old_revision": old_rev, "new_revision": new_config.policy_revision},
            policy_revision=new_config.policy_revision,
        )
        self._publish()

    def _shutdown(self, *, force: bool) -> None:
        self._ops.mark_shutdown()
        self._publish()
        deadline = self._clock.monotonic() + (
            0 if force else self._pipeline_config.graceful_drain_seconds
        )
        while not force and self._clock.monotonic() < deadline:
            obs = self._observations.get(timeout=0.05)
            if obs is None:
                if self._observations.qsize() == 0:
                    break
                continue
            self._handle_observation(obs)
        now = self._clock.monotonic()
        for transition in self._tracker.close_all("shutdown", lifecycle_time=now):
            envelope = self._sequencer.wrap_episode(
                transition, emitted_at=datetime.now(UTC)
            )
            self._evidence.commit(envelope)
            self._notifier.notify(envelope)
        self._evidence.flush()
        self._notifier.stop(
            drain_seconds=self._config.notifications.shutdown_drain_seconds
        )
        self._stop.set()

    def _commit_system(
        self,
        name: str,
        fields: dict[str, object],
        *,
        policy_revision: str | None = None,
    ) -> None:
        cleaned = {key: value for key, value in fields.items() if value is not None}
        envelope = self._sequencer.wrap_system(
            name,  # type: ignore[arg-type]
            cleaned,
            emitted_at=datetime.now(UTC),
            policy_revision=policy_revision
            if policy_revision is not None
            else self._config.policy_revision,
        )
        self._evidence.commit(envelope)
        self._notifier.notify(envelope)

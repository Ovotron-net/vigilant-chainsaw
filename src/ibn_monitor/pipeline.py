from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .config import ConfigSource, PolicyV2Config
from .evidence import EvidenceWriter
from .models import (
    ControlMessage,
    Observation,
    OperationalSnapshot,
)
from .notifications_v2 import NullV2Notifier, V2Notifier
from .ops_state import OperationalStateMachine
from .processing import Envelopes, EpisodeProcessor
from .read_model import ReadModel

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
        self._lifecycle: deque[ControlMessage] = deque()
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
                self._lifecycle.append(message)
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
            messages.extend(self._lifecycle)
            self._lifecycle.clear()
            while self._items:
                messages.append(self._items.popleft())
            if self._shutdown is not None:
                messages.append(self._shutdown)
                self._shutdown = None
            return messages

    def wait(self, timeout: float) -> None:
        with self._not_empty:
            self._not_empty.wait(timeout)


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    observation_capacity: int
    queue_recovery_cooldown_seconds: float
    graceful_drain_seconds: float
    timer_interval_seconds: float = 0.25
    config_source: ConfigSource | None = None


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
        self._pipeline_config = pipeline_config
        self._evidence = evidence
        self._notifier: V2Notifier = notifier or NullV2Notifier()
        self._clock = clock or time
        self._processor = EpisodeProcessor(config, boot_id=boot_id)
        self._observations = ObservationQueue(pipeline_config.observation_capacity)
        self._control = ControlLane()
        self._ops = OperationalStateMachine(
            sensor_id=config.sensor.id,
            boot_id=boot_id,
            queue_capacity=pipeline_config.observation_capacity,
            sources=tuple((point.name, point.interface) for point in config.sensor.capture_points),
        )
        self._ops.set_policy(config.policy_revision, config.config_revision)
        self._read_model = ReadModel()
        self._read_model.set_rules(config.rules)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._force = False
        self._app_drop_incident_start: float | None = None
        self._kernel_drop_incident_start: float | None = None
        self._last_app_drop_mono = 0.0
        self._last_kernel_drop_mono = 0.0
        self._timer_thread: threading.Thread | None = None
        self._publish(episodes=True)

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
        snapshot = self._read_model.ops_snapshot()
        assert snapshot is not None  # published in __init__
        return snapshot

    def operations_state(self) -> dict[str, object]:
        return self._read_model.view()

    def metrics_text(self) -> str:
        return self._read_model.metrics_text()

    def _publish(self, *, episodes: bool = False) -> None:
        """Project worker state for HTTP readers.

        Active episodes are copied only when ``episodes`` is set (timer ticks,
        reloads, shutdown) so per-Observation publishing stays O(1) in episodes.
        """
        self._ops.set_queue_depth(self._observations.qsize())
        self._ops.set_journal_healthy(self._evidence.healthy)
        self._read_model.publish(
            ops=self._ops.snapshot(),
            counts=self._processor.counts(),
            journal_healthy=self._evidence.healthy,
            notifier=self._notifier.stats(),
            active_episodes=self._processor.active_episodes() if episodes else None,
        )

    def _timer_loop(self) -> None:
        while not self._stop.is_set():
            self._control.put(ControlMessage(kind="timer", monotonic_at=self._clock.monotonic()))
            self._stop.wait(self._pipeline_config.timer_interval_seconds)

    def _run(self) -> None:
        try:
            while True:
                timers: list[ControlMessage] = []
                for message in self._control.drain():
                    if message.kind == "timer":
                        timers.append(message)
                        continue
                    self._handle_control(message)
                    if message.kind == "force_shutdown" or (
                        message.kind == "shutdown" and self._force
                    ):
                        self._shutdown(force=True)
                        return
                    if message.kind == "shutdown":
                        self._shutdown(force=False)
                        return
                # A timer must not advance episode time past observations that were
                # already queued when the timer was drained.
                observation_limit = self._observations.qsize() if timers else OBSERVATION_BATCH
                processed = 0
                for _ in range(observation_limit):
                    obs = self._observations.get(timeout=0.0)
                    if obs is None:
                        break
                    self._handle_observation(obs)
                    processed += 1
                for timer in timers:
                    self._handle_control(timer)
                if not timers and processed == OBSERVATION_BATCH:
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

    def _emit(self, envelopes: Envelopes) -> None:
        for envelope in envelopes:
            self._evidence.commit(envelope)
            self._read_model.note_envelope(envelope)
            self._notifier.notify(envelope)

    def _handle_observation(self, observation: Observation) -> None:
        lifecycle = (
            observation.monotonic_at
            if observation.monotonic_at is not None
            else self._clock.monotonic()
        )
        self._emit(
            self._processor.observe(
                observation, lifecycle_time=lifecycle, emitted_at=datetime.now(UTC)
            )
        )
        self._publish()

    def _handle_control(self, message: ControlMessage) -> None:
        if message.kind == "timer":
            now = message.monotonic_at
            self._evidence.maintain()
            self._emit(self._processor.tick(lifecycle_time=now, emitted_at=datetime.now(UTC)))
            self._maybe_clear_drop_reasons(now)
            self._publish(episodes=True)
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
        emitted_at = datetime.now(UTC)
        source = self._pipeline_config.config_source
        try:
            if source is None:
                raise RuntimeError("no config source to reload from")
            new_config = source.load()
        except Exception as exc:
            self._emit(self._processor.reload_failed(str(exc), emitted_at=emitted_at))
            self._publish()
            return
        before = self._processor.config
        self._emit(
            self._processor.reload(
                new_config, lifecycle_time=self._clock.monotonic(), emitted_at=emitted_at
            )
        )
        after = self._processor.config
        if after is not before:
            self._read_model.set_rules(after.rules)
            self._ops.set_policy(after.policy_revision, after.config_revision)
        self._publish(episodes=True)

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
        self._emit(
            self._processor.close_all(
                "shutdown", lifecycle_time=self._clock.monotonic(), emitted_at=datetime.now(UTC)
            )
        )
        self._publish(episodes=True)
        self._evidence.flush(mark_clean=not force)
        self._notifier.stop(
            drain_seconds=self._processor.config.notifications.shutdown_drain_seconds
        )
        self._stop.set()

    def _commit_system(self, name: str, fields: dict[str, object]) -> None:
        self._emit(
            self._processor.system(
                name,  # type: ignore[arg-type]
                fields,
                emitted_at=datetime.now(UTC),
            )
        )

from __future__ import annotations

import logging
from dataclasses import dataclass

from .models import (
    REASON_APP_QUEUE_DROPS,
    REASON_CAPTURE_POINT_UNAVAILABLE,
    REASON_KERNEL_DROPS,
    REASON_NO_POLICY,
    REASON_SHUTDOWN,
    REASON_WORKER_DEAD,
    OperationalSnapshot,
    OperationalStateName,
    SourceLifecycleState,
    SourceStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class _SourceRuntime:
    capture_point: str
    interface: str
    state: SourceLifecycleState = "starting"
    source_generation: str | None = None
    last_error: str | None = None
    kernel_packets: int = 0
    kernel_drops: int = 0


class OperationalStateMachine:
    def __init__(
        self,
        *,
        sensor_id: str,
        boot_id: str,
        queue_capacity: int,
        sources: tuple[tuple[str, str], ...],
    ) -> None:
        self._sensor_id = sensor_id
        self._boot_id = boot_id
        self._queue_capacity = queue_capacity
        self._state: OperationalStateName = "starting"
        self._reasons: set[str] = set()
        self._policy_revision: str | None = None
        self._config_revision: str | None = None
        self._queue_depth = 0
        self._app_queue_drops_total = 0
        self._kernel_drops_total = 0
        self._sources = {
            name: _SourceRuntime(capture_point=name, interface=iface)
            for name, iface in sources
        }
        self._last_kernel_drops: dict[str, int] = {name: 0 for name, _ in sources}

    def set_policy(self, policy_revision: str | None, config_revision: str | None) -> None:
        self._policy_revision = policy_revision
        self._config_revision = config_revision
        if policy_revision:
            self._reasons.discard(REASON_NO_POLICY)
        else:
            self._reasons.add(REASON_NO_POLICY)
        self._recompute()

    def set_queue_depth(self, depth: int) -> None:
        self._queue_depth = depth

    def note_app_drops(self, count: int) -> None:
        if count <= 0:
            return
        self._app_queue_drops_total += count
        self._reasons.add(REASON_APP_QUEUE_DROPS)
        self._recompute()

    def clear_app_drops(self) -> None:
        self._reasons.discard(REASON_APP_QUEUE_DROPS)
        self._recompute()

    def note_kernel_drops(self, capture_point: str, total: int) -> int:
        previous = self._last_kernel_drops.get(capture_point, 0)
        delta = max(0, total - previous)
        self._last_kernel_drops[capture_point] = total
        if delta:
            self._kernel_drops_total += delta
            self._reasons.add(REASON_KERNEL_DROPS)
            self._recompute()
        return delta

    def clear_kernel_drops(self) -> None:
        self._reasons.discard(REASON_KERNEL_DROPS)
        self._recompute()

    def set_source(
        self,
        capture_point: str,
        *,
        state: SourceLifecycleState,
        source_generation: str | None = None,
        last_error: str | None = None,
        kernel_packets: int | None = None,
        kernel_drops: int | None = None,
    ) -> None:
        source = self._sources[capture_point]
        source.state = state
        if source_generation is not None:
            source.source_generation = source_generation
        if last_error is not None or state in {"established", "stopped"}:
            source.last_error = last_error
        if kernel_packets is not None:
            source.kernel_packets = kernel_packets
        if kernel_drops is not None:
            source.kernel_drops = kernel_drops
        self._refresh_capture_reason()
        self._recompute()

    def mark_shutdown(self) -> None:
        self._reasons.add(REASON_SHUTDOWN)
        self._state = "stopping"
        self._recompute()

    def mark_worker_dead(self) -> None:
        self._reasons.add(REASON_WORKER_DEAD)
        self._recompute()

    def _refresh_capture_reason(self) -> None:
        if any(source.state != "established" for source in self._sources.values()):
            if self._state != "stopping" and REASON_SHUTDOWN not in self._reasons:
                self._reasons.add(REASON_CAPTURE_POINT_UNAVAILABLE)
        else:
            self._reasons.discard(REASON_CAPTURE_POINT_UNAVAILABLE)

    def _recompute(self) -> None:
        if REASON_SHUTDOWN in self._reasons or self._state == "stopping":
            self._state = "stopping"
        elif self._reasons:
            self._state = "degraded" if self._state != "starting" or self._reasons else "starting"
            if self._state == "starting" and (
                self._reasons - {REASON_CAPTURE_POINT_UNAVAILABLE}
                or (
                    REASON_CAPTURE_POINT_UNAVAILABLE in self._reasons
                    and any(s.state == "failed" for s in self._sources.values())
                )
            ):
                self._state = "degraded"
        elif (
            all(s.state == "established" for s in self._sources.values())
            and self._policy_revision
        ):
            self._state = "ready"
        else:
            self._state = "starting"
        self._log_state()

    def _log_state(self) -> None:
        logger.info(
            "operational_state ibn_state=%s ibn_reasons=%s ibn_ready=%s "
            "ibn_policy_revision=%s ibn_boot_id=%s",
            self._state,
            sorted(self._reasons),
            self._state == "ready",
            self._policy_revision,
            self._boot_id,
        )

    def snapshot(self) -> OperationalSnapshot:
        sources = tuple(
            SourceStatus(
                capture_point=source.capture_point,
                interface=source.interface,
                state=source.state,
                source_generation=source.source_generation,
                last_error=source.last_error,
                kernel_packets=source.kernel_packets,
                kernel_drops=source.kernel_drops,
            )
            for source in sorted(self._sources.values(), key=lambda item: item.capture_point)
        )
        return OperationalSnapshot(
            state=self._state,
            reasons=frozenset(self._reasons),
            ready=self._state == "ready",
            policy_revision=self._policy_revision,
            config_revision=self._config_revision,
            sources=sources,
            queue_depth=self._queue_depth,
            queue_capacity=self._queue_capacity,
            app_queue_drops_total=self._app_queue_drops_total,
            kernel_drops_total=self._kernel_drops_total,
            boot_id=self._boot_id,
            sensor_id=self._sensor_id,
        )

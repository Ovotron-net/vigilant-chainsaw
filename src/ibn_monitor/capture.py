"""V2 capture seam: ObservationSource protocol and in-memory test adapter.

Live AF_PACKET implementation lives in ``capture_afpacket.py`` (Linux only).
Classic-PCAP offline analysis uses ``replay`` / ``pcap.py`` — not this module.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .models import ControlMessage, Observation, SourceStatsSnapshot

ObservationSink = Callable[[Observation], None]
ControlSink = Callable[[ControlMessage], None]


class ObservationSource(Protocol):
    """V2 live capture seam: one logical capture point (or test double)."""

    @property
    def capture_point(self) -> str: ...

    def start(
        self,
        observation_sink: ObservationSink,
        control_sink: ControlSink,
    ) -> None: ...

    def stop(self) -> None: ...


class MemoryObservationSource:
    """In-memory ObservationSource for pure tests."""

    def __init__(self, capture_point: str, *, auto_establish: bool = True) -> None:
        self._capture_point = capture_point
        self._auto_establish = auto_establish
        self._observation_sink: ObservationSink | None = None
        self._control_sink: ControlSink | None = None
        self._generation = f"{capture_point}:test:1"
        self.stopped = False

    @property
    def capture_point(self) -> str:
        return self._capture_point

    def start(
        self,
        observation_sink: ObservationSink,
        control_sink: ControlSink,
    ) -> None:
        self.stopped = False
        self._observation_sink = observation_sink
        self._control_sink = control_sink
        if self._auto_establish:
            self.emit_established(self._generation)

    def stop(self) -> None:
        self.stopped = True
        if self._control_sink is not None:
            self._control_sink(
                ControlMessage(
                    kind="source_stopped",
                    monotonic_at=0.0,
                    capture_point=self._capture_point,
                    source_generation=self._generation,
                )
            )

    def push(self, observation: Observation) -> None:
        if self._observation_sink is None:
            raise RuntimeError("source not started")
        self._observation_sink(observation)

    def emit_failed(self, reason: str) -> None:
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_failed",
                monotonic_at=0.0,
                capture_point=self._capture_point,
                detail=reason,
            )
        )

    def emit_stats(self, stats: SourceStatsSnapshot) -> None:
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_stats",
                monotonic_at=0.0,
                capture_point=stats.capture_point,
                source_generation=stats.source_generation,
                stats=stats,
            )
        )

    def emit_established(self, source_generation: str) -> None:
        self._generation = source_generation
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_established",
                monotonic_at=0.0,
                capture_point=self._capture_point,
                source_generation=source_generation,
            )
        )

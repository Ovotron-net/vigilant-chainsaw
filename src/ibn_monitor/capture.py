"""V2 capture seam: ObservationSource, the shared live capture lifecycle, and test doubles.

A live ObservationSource is ``CaptureSource`` (lifecycle: thread, reconnect with
backoff, decode with fallback, outcome counts, stats, generation events) around
a platform ``CaptureAdapter`` (open, read one header, kernel stats, close):

- Windows: ``capture_windows.WindowsRawAdapter`` (raw IPv4 / SIO_RCVALL)
- Linux: ``capture_afpacket.AfPacketAdapter`` (AF_PACKET + owned cBPF)

``capture_live.build_live_sources`` picks the adapter for the running OS.
Classic-PCAP offline analysis uses ``replay`` / ``pcap.py`` — not this module.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .config import CapturePointConfig
from .decode import HeaderReader, ObservationContext, decode_observation
from .models import ControlKind, ControlMessage, Observation, ObservedDirection, SourceStatsSnapshot

logger = logging.getLogger(__name__)

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


@dataclass(frozen=True, slots=True)
class CapturedHeader:
    """One datagram's header bytes as delivered by an adapter.

    ``release`` must run after decoding (AF_PACKET consumes its MSG_PEEK there).
    """

    reader: HeaderReader
    direction: ObservedDirection
    captured_at: datetime | None = None
    release: Callable[[], None] | None = None


class CaptureAdapter(Protocol):
    """Platform half of a live ObservationSource. Methods run on the capture thread.

    ``open`` and ``read`` raise on failure; the source then reports the failure,
    closes the adapter and retries ``open`` with backoff.
    """

    link_type: int

    def open(self) -> str:
        """Open the capture; return a short description for logs."""
        ...

    def read(self) -> CapturedHeader | None:
        """Return the next header, or ``None`` after a read timeout."""
        ...

    def poll_kernel_stats(self) -> tuple[int, int]:
        """Return (packets, drops) seen by the kernel since the previous poll."""
        ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class CaptureSourceConfig:
    sensor_id: str
    capture_point: CapturePointConfig
    boot_id: str
    stats_poll_interval_seconds: float = 1.0
    reopen_backoff_initial_seconds: float = 1.0
    reopen_backoff_max_seconds: float = 30.0


class CaptureSource:
    """Live ObservationSource: shared lifecycle around one platform adapter."""

    def __init__(self, config: CaptureSourceConfig, adapter: CaptureAdapter) -> None:
        self._config = config
        self._adapter = adapter
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._observation_sink: ObservationSink | None = None
        self._control_sink: ControlSink | None = None
        self._generation_counter = 0
        self._source_generation: str | None = None
        self._kernel_packets = 0
        self._kernel_drops = 0
        self._enqueued = 0
        self._outcomes = {"complete": 0, "partial": 0, "undecodable": 0}

    @property
    def capture_point(self) -> str:
        return self._config.capture_point.name

    def start(self, observation_sink: ObservationSink, control_sink: ControlSink) -> None:
        self._observation_sink = observation_sink
        self._control_sink = control_sink
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"ibn-capture-{self.capture_point}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._emit("source_stopped", source_generation=self._source_generation)

    def _emit(self, kind: ControlKind, **fields: object) -> None:
        if self._control_sink is not None:
            self._control_sink(
                ControlMessage(
                    kind=kind,
                    monotonic_at=time.monotonic(),
                    capture_point=self.capture_point,
                    **fields,  # type: ignore[arg-type]
                )
            )

    def _run(self) -> None:
        backoff = self._config.reopen_backoff_initial_seconds
        while not self._stop.is_set():
            try:
                description = self._adapter.open()
                self._generation_counter += 1
                self._source_generation = (
                    f"{self.capture_point}:{self._config.boot_id}:{self._generation_counter}"
                )
                self._emit(
                    "source_established" if self._generation_counter == 1 else "source_recovered",
                    source_generation=self._source_generation,
                )
                logger.info("capture established point=%s %s", self.capture_point, description)
                backoff = self._config.reopen_backoff_initial_seconds
                self._read_loop()
                self._adapter.close()
            except Exception as exc:
                logger.error("capture %s failed: %s", self.capture_point, exc)
                self._emit(
                    "source_failed", source_generation=self._source_generation, detail=str(exc)
                )
                self._adapter.close()
                if self._stop.is_set():
                    return
                self._emit("source_retrying", detail=str(exc))
                self._stop.wait(backoff)
                backoff = min(backoff * 2, self._config.reopen_backoff_max_seconds)

    def _read_loop(self) -> None:
        last_stats = time.monotonic()
        while not self._stop.is_set():
            header = self._adapter.read()
            if header is not None:
                self._deliver(header)
            now = time.monotonic()
            if now - last_stats >= self._config.stats_poll_interval_seconds:
                last_stats = now
                self._emit_stats()

    def _deliver(self, header: CapturedHeader) -> None:
        ctx = ObservationContext(
            captured_at=header.captured_at or datetime.now(UTC),
            monotonic_at=time.monotonic(),
            sensor_id=self._config.sensor_id,
            source_generation=self._source_generation or "",
            capture_point=self.capture_point,
            interface=self._config.capture_point.interface,
            direction=header.direction,
        )
        try:
            observation = decode_observation(header.reader, self._adapter.link_type, ctx)
        except Exception:
            observation = Observation(
                captured_at=ctx.captured_at,
                monotonic_at=ctx.monotonic_at,
                sensor_id=ctx.sensor_id,
                source_generation=ctx.source_generation,
                capture_point=ctx.capture_point,
                interface=ctx.interface,
                direction=ctx.direction,
                wire_length=header.reader.wire_length,
                outcome="undecodable",
                decode_reason="decode_exception",
            )
        finally:
            if header.release is not None:
                header.release()
        self._outcomes[observation.outcome or "undecodable"] += 1
        if self._observation_sink is not None:
            self._observation_sink(observation)
            self._enqueued += 1

    def _emit_stats(self) -> None:
        try:
            packets, drops = self._adapter.poll_kernel_stats()
        except OSError:
            packets, drops = 0, 0
        self._kernel_packets += packets
        self._kernel_drops += drops
        self._emit(
            "source_stats",
            source_generation=self._source_generation,
            stats=SourceStatsSnapshot(
                capture_point=self.capture_point,
                source_generation=self._source_generation or "",
                kernel_packets=self._kernel_packets,
                kernel_drops=self._kernel_drops,
                app_enqueue_ok=self._enqueued,
                # Queue drops are counted by the pipeline worker, which owns the queue.
                app_enqueue_drops=0,
                decode_complete=self._outcomes["complete"],
                decode_partial=self._outcomes["partial"],
                decode_undecodable=self._outcomes["undecodable"],
            ),
        )


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

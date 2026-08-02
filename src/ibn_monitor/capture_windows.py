"""Windows raw-IP ObservationSource (SIO_RCVALL) — win32 only.

Delivers L3 headers without Ethernet framing; decode uses DLT_RAW.
Requires Administrator for SOCK_RAW + RCVALL.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import CapturePointConfig, PolicyV2Config
from .decode import DLT_RAW, ObservationContext, decode_observation
from .models import ControlMessage, Observation, SourceStatsSnapshot
from .windows_packet import require_windows, resolve_bind_ipv4

logger = logging.getLogger(__name__)

# socket.SIO_RCVALL / RCVALL_ON exist on Windows CPython
_SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
_RCVALL_ON = getattr(socket, "RCVALL_ON", 1)
_RCVALL_OFF = getattr(socket, "RCVALL_OFF", 0)


@dataclass(frozen=True, slots=True)
class WindowsRawSourceConfig:
    sensor_id: str
    capture_point: CapturePointConfig
    boot_id: str
    header_budget: int = 512
    stats_poll_interval_seconds: float = 1.0
    reopen_backoff_initial_seconds: float = 1.0
    reopen_backoff_max_seconds: float = 30.0
    recv_timeout_seconds: float = 0.25


def build_windows_raw_sources(
    config: PolicyV2Config, *, boot_id: str
) -> tuple[WindowsRawSource, ...]:
    return tuple(
        WindowsRawSource(
            WindowsRawSourceConfig(
                sensor_id=config.sensor.id,
                capture_point=point,
                boot_id=boot_id,
            )
        )
        for point in config.sensor.capture_points
    )


class _BytesHeaderReader:
    """Minimal HeaderReader over a complete IP datagram buffer."""

    __slots__ = ("_data", "wire_length")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.wire_length = len(data)

    def prefix(self, length: int) -> bytes:
        return self._data[:length]


class WindowsRawSource:
    """win32 ObservationSource: one capture point via raw IPv4 socket."""

    def __init__(self, config: WindowsRawSourceConfig) -> None:
        if sys.platform != "win32":
            raise RuntimeError("WindowsRawSource requires win32")
        self._config = config
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._observation_sink = None
        self._control_sink = None
        self._generation_counter = 0
        self._source_generation: str | None = None
        self._kernel_packets = 0
        self._kernel_drops = 0
        self._app_ok = 0
        self._app_drops = 0
        self._decode_complete = 0
        self._decode_partial = 0
        self._decode_undecodable = 0
        self._bind_ipv4: str | None = None

    @property
    def capture_point(self) -> str:
        return self._config.capture_point.name

    def start(self, observation_sink, control_sink) -> None:
        self._observation_sink = observation_sink
        self._control_sink = control_sink
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"ibn-capture-{self.capture_point}",
            daemon=True,
        )
        self._thread.start()
        time.sleep(0.05)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._emit(
            ControlMessage(
                kind="source_stopped",
                monotonic_at=time.monotonic(),
                capture_point=self.capture_point,
                source_generation=self._source_generation,
            )
        )

    def _emit(self, message: ControlMessage) -> None:
        if self._control_sink is not None:
            self._control_sink(message)

    def _new_generation(self) -> str:
        self._generation_counter += 1
        return (
            f"{self.capture_point}:{self._config.boot_id}:{self._generation_counter}"
        )

    def _run(self) -> None:
        require_windows()
        backoff = self._config.reopen_backoff_initial_seconds
        while not self._stop.is_set():
            sock: socket.socket | None = None
            try:
                bind_ip = resolve_bind_ipv4(self._config.capture_point.interface)
                self._bind_ipv4 = bind_ip
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((bind_ip, 0))
                sock.ioctl(_SIO_RCVALL, _RCVALL_ON)
                sock.settimeout(self._config.recv_timeout_seconds)

                self._source_generation = self._new_generation()
                self._emit(
                    ControlMessage(
                        kind="source_established"
                        if self._generation_counter == 1
                        else "source_recovered",
                        monotonic_at=time.monotonic(),
                        capture_point=self.capture_point,
                        source_generation=self._source_generation,
                    )
                )
                logger.info(
                    "Windows raw capture established point=%s bind=%s interface=%s",
                    self.capture_point,
                    bind_ip,
                    self._config.capture_point.interface,
                )
                backoff = self._config.reopen_backoff_initial_seconds
                self._recv_loop(sock)
            except Exception as exc:
                logger.error("capture %s failed: %s", self.capture_point, exc)
                self._emit(
                    ControlMessage(
                        kind="source_failed",
                        monotonic_at=time.monotonic(),
                        capture_point=self.capture_point,
                        source_generation=self._source_generation,
                        detail=str(exc),
                    )
                )
                if sock is not None:
                    with contextlib.suppress(OSError):
                        sock.ioctl(_SIO_RCVALL, _RCVALL_OFF)
                    with contextlib.suppress(OSError):
                        sock.close()
                if self._stop.is_set():
                    return
                self._emit(
                    ControlMessage(
                        kind="source_retrying",
                        monotonic_at=time.monotonic(),
                        capture_point=self.capture_point,
                        detail=str(exc),
                    )
                )
                self._stop.wait(backoff)
                backoff = min(backoff * 2, self._config.reopen_backoff_max_seconds)

    def _recv_loop(self, sock: socket.socket) -> None:
        last_stats = time.monotonic()
        budget = self._config.header_budget
        while not self._stop.is_set():
            try:
                data = sock.recv(budget)
            except TimeoutError:
                now = time.monotonic()
                if now - last_stats >= self._config.stats_poll_interval_seconds:
                    last_stats = now
                    self._emit_stats()
                continue
            except OSError as exc:
                raise RuntimeError(str(exc)) from exc

            if not data:
                continue
            self._kernel_packets += 1
            # CaptureDirection includes "both"; Observation uses inbound|outbound|unknown.
            cap_dir = self._config.capture_point.direction
            obs_dir = cap_dir if cap_dir in {"inbound", "outbound"} else "unknown"
            ctx = ObservationContext(
                captured_at=datetime.now(UTC),
                monotonic_at=time.monotonic(),
                sensor_id=self._config.sensor_id,
                source_generation=self._source_generation or "",
                capture_point=self.capture_point,
                interface=self._config.capture_point.interface,
                direction=obs_dir,  # type: ignore[arg-type]
            )
            reader = _BytesHeaderReader(data)
            try:
                obs = decode_observation(reader, DLT_RAW, ctx)
            except Exception:
                obs = Observation(
                    captured_at=ctx.captured_at,
                    monotonic_at=ctx.monotonic_at,
                    sensor_id=ctx.sensor_id,
                    source_generation=ctx.source_generation,
                    capture_point=ctx.capture_point,
                    interface=ctx.interface,
                    direction=ctx.direction,
                    wire_length=reader.wire_length,
                    outcome="undecodable",
                    decode_reason="decode_exception",
                )
            if obs.outcome == "complete":
                self._decode_complete += 1
            elif obs.outcome == "partial":
                self._decode_partial += 1
            else:
                self._decode_undecodable += 1
            if self._observation_sink is not None:
                self._observation_sink(obs)
                self._app_ok += 1

            now = time.monotonic()
            if now - last_stats >= self._config.stats_poll_interval_seconds:
                last_stats = now
                self._emit_stats()

        with contextlib.suppress(OSError):
            sock.ioctl(_SIO_RCVALL, _RCVALL_OFF)
        with contextlib.suppress(OSError):
            sock.close()

    def _emit_stats(self) -> None:
        self._emit(
            ControlMessage(
                kind="source_stats",
                monotonic_at=time.monotonic(),
                capture_point=self.capture_point,
                source_generation=self._source_generation,
                stats=SourceStatsSnapshot(
                    capture_point=self.capture_point,
                    source_generation=self._source_generation or "",
                    kernel_packets=self._kernel_packets,
                    kernel_drops=self._kernel_drops,
                    app_enqueue_ok=self._app_ok,
                    app_enqueue_drops=self._app_drops,
                    decode_complete=self._decode_complete,
                    decode_partial=self._decode_partial,
                    decode_undecodable=self._decode_undecodable,
                ),
            )
        )

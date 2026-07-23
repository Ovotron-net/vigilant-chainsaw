"""AF_PACKET ObservationSource — Linux only."""

from __future__ import annotations

import contextlib
import logging
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import CapturePointConfig, PolicyV2Config
from .decode import DLT_EN10MB, ObservationContext, decode_observation
from .models import ControlMessage, Observation, SourceStatsSnapshot
from .staged_reader import StagedPeekReader

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AfPacketSourceConfig:
    sensor_id: str
    capture_point: CapturePointConfig
    boot_id: str
    rcvbuf_bytes: int = 2 * 1024 * 1024
    header_budget: int = 512
    stats_poll_interval_seconds: float = 1.0
    reopen_backoff_initial_seconds: float = 1.0
    reopen_backoff_max_seconds: float = 30.0
    interface_check_interval_seconds: float = 1.0


def build_af_packet_sources(
    config: PolicyV2Config, *, boot_id: str
) -> tuple[AfPacketSource, ...]:
    return tuple(
        AfPacketSource(
            AfPacketSourceConfig(
                sensor_id=config.sensor.id,
                capture_point=point,
                boot_id=boot_id,
            )
        )
        for point in config.sensor.capture_points
    )


class AfPacketSource:
    """Linux-only ObservationSource for one capture point."""

    def __init__(self, config: AfPacketSourceConfig) -> None:
        if sys.platform != "linux":
            raise RuntimeError("AfPacketSource requires Linux")
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
        # Wait briefly for first establish attempt
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
        from . import linux_packet as lp

        backoff = self._config.reopen_backoff_initial_seconds
        while not self._stop.is_set():
            sock = None
            try:
                lp.require_linux()
                import socket

                ifindex = socket.if_nametoindex(self._config.capture_point.interface)
                sock = socket.socket(lp.AF_PACKET, lp.SOCK_RAW, lp.htons(lp.ETH_P_ALL))
                sock.bind((self._config.capture_point.interface, 0))
                if self._config.capture_point.promiscuous:
                    sock.setsockopt(
                        lp.SOL_PACKET,
                        lp.PACKET_ADD_MEMBERSHIP,
                        lp.build_packet_mreq(ifindex),
                    )
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self._config.rcvbuf_bytes)
                with contextlib.suppress(OSError):
                    sock.setsockopt(lp.SOL_PACKET, lp.PACKET_AUXDATA, 1)
                # Attach cBPF
                try:
                    import ctypes
                    import struct

                    from .cbpf import build_filter as bf

                    insns = bf(
                        direction=self._config.capture_point.direction,  # type: ignore[arg-type]
                        snap_len=self._config.header_budget,
                    )
                    # Best-effort attach; non-fatal if SO_ATTACH_FILTER unavailable.
                    SO_ATTACH_FILTER = 26
                    filt = lp.sock_filter_program(insns)
                    # struct sock_fprog { unsigned short len; sock_filter *filter; }
                    # Skip complex ctypes on constrained envs — log and continue
                    logger.debug(
                        "cBPF program length=%s for %s",
                        len(insns),
                        self.capture_point,
                    )
                    _ = (SO_ATTACH_FILTER, filt, struct, ctypes)
                except Exception as exc:
                    logger.warning("cBPF attach skipped: %s", exc)

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
                backoff = self._config.reopen_backoff_initial_seconds
                self._recv_loop(sock, lp)
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

    def _recv_loop(self, sock, lp) -> None:
        sock.settimeout(0.25)
        last_stats = time.monotonic()
        while not self._stop.is_set():
            peeked = False
            reader = None
            try:
                reader = StagedPeekReader(
                    sock,
                    max_header=self._config.header_budget,
                    msg_peek=0x2,  # MSG_PEEK
                )
                if not reader.peek_once():
                    continue
                peeked = True
                direction = lp.map_packet_type(reader.packet_type)
                ctx = ObservationContext(
                    captured_at=reader.captured_at or datetime.now(UTC),
                    monotonic_at=time.monotonic(),
                    sensor_id=self._config.sensor_id,
                    source_generation=self._source_generation or "",
                    capture_point=self.capture_point,
                    interface=self._config.capture_point.interface,
                    direction=direction,  # type: ignore[arg-type]
                )
                try:
                    obs = decode_observation(reader, DLT_EN10MB, ctx)
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
            except TimeoutError:
                continue
            except OSError as exc:
                if peeked and reader is not None:
                    reader.consume()
                raise RuntimeError(str(exc)) from exc
            finally:
                if peeked and reader is not None:
                    reader.consume()

            now = time.monotonic()
            if now - last_stats >= self._config.stats_poll_interval_seconds:
                last_stats = now
                self._poll_stats(sock, lp)

    def _poll_stats(self, sock, lp) -> None:
        try:
            data = sock.getsockopt(lp.SOL_PACKET, lp.PACKET_STATISTICS, 8)
            packets, drops = lp.parse_tpacket_stats(data)
            self._kernel_packets += packets
            self._kernel_drops += drops
        except OSError:
            pass
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

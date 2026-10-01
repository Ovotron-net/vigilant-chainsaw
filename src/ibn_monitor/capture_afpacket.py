"""AF_PACKET capture adapter with the owned cBPF filter — Linux only."""

from __future__ import annotations

import contextlib
import ctypes
import logging
import socket
import struct

from . import linux_packet as lp
from .capture import CapturedHeader, CaptureSource, CaptureSourceConfig
from .cbpf import build_filter
from .config import CapturePointConfig, PolicyV2Config
from .decode import DLT_EN10MB
from .staged_reader import StagedPeekReader

logger = logging.getLogger(__name__)

SO_ATTACH_FILTER = 26
MSG_PEEK = 0x2
MSG_TRUNC = 0x20


def build_af_packet_sources(config: PolicyV2Config, *, boot_id: str) -> tuple[CaptureSource, ...]:
    return tuple(
        CaptureSource(
            CaptureSourceConfig(sensor_id=config.sensor.id, capture_point=point, boot_id=boot_id),
            AfPacketAdapter(point),
        )
        for point in config.sensor.capture_points
    )


def pack_sock_fprog(program: bytes) -> tuple[bytes, ctypes.Array[ctypes.c_char]]:
    """Build ``struct sock_fprog { unsigned short len; struct sock_filter *filter; }``.

    Returns the packed struct plus the buffer it points into; the caller must keep
    the buffer alive until ``setsockopt`` returns (the kernel copies the program).
    """
    if len(program) % 8:
        raise ValueError("cBPF program must be a whole number of 8-byte sock_filter entries")
    buffer = ctypes.create_string_buffer(program, len(program))
    return struct.pack("HP", len(program) // 8, ctypes.addressof(buffer)), buffer


class AfPacketAdapter:
    """CaptureAdapter: AF_PACKET socket on one interface, owned cBPF, MSG_PEEK headers."""

    link_type = DLT_EN10MB

    def __init__(
        self,
        capture_point: CapturePointConfig,
        *,
        header_budget: int = 512,
        rcvbuf_bytes: int = 2 * 1024 * 1024,
        recv_timeout_seconds: float = 0.25,
    ) -> None:
        self._point = capture_point
        self._header_budget = header_budget
        self._rcvbuf_bytes = rcvbuf_bytes
        self._recv_timeout = recv_timeout_seconds
        self._sock: socket.socket | None = None
        self._filtered = False

    def open(self) -> str:
        lp.require_linux()
        interface = self._point.interface
        ifindex = socket.if_nametoindex(interface)
        sock = socket.socket(lp.AF_PACKET, lp.SOCK_RAW, lp.htons(lp.ETH_P_ALL))
        self._sock = sock
        sock.bind((interface, 0))
        if self._point.promiscuous:
            sock.setsockopt(lp.SOL_PACKET, lp.PACKET_ADD_MEMBERSHIP, lp.build_packet_mreq(ifindex))
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self._rcvbuf_bytes)
        with contextlib.suppress(OSError):
            sock.setsockopt(lp.SOL_PACKET, lp.PACKET_AUXDATA, 1)
        self._filtered = self._attach_filter(sock)
        sock.settimeout(self._recv_timeout)
        return f"af_packet interface={interface} cbpf={'on' if self._filtered else 'off'}"

    def _attach_filter(self, sock: socket.socket) -> bool:
        """Best effort: without the filter the sensor still works, just unfiltered."""
        program = lp.sock_filter_program(
            build_filter(direction=self._point.direction, snap_len=self._header_budget)
        )
        fprog, _buffer = pack_sock_fprog(program)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        except OSError as exc:
            logger.warning("cBPF attach failed on %s: %s", self._point.interface, exc)
            return False
        return True

    def read(self) -> CapturedHeader | None:
        assert self._sock is not None
        buffer = bytearray(self._header_budget)
        try:
            wire_length, _ancillary, _flags, address = self._sock.recvmsg_into(
                [buffer], 0, MSG_PEEK | MSG_TRUNC
            )
        except TimeoutError:
            return None
        if wire_length <= 0:
            return None
        packet_type = int(address[2])
        direction = lp.map_packet_type(packet_type)
        reader = StagedPeekReader(
            self._sock,
            max_header=self._header_budget,
            msg_peek=MSG_PEEK,
            wire_length=wire_length,
            packet_type=packet_type,
            prefetched=bytes(buffer[: min(wire_length, self._header_budget)]),
        )
        if not self._filtered and self._point.direction not in {"both", direction}:
            reader.consume()
            return None
        return CapturedHeader(
            reader=reader,
            direction=direction,  # type: ignore[arg-type]
            captured_at=reader.captured_at,
            release=reader.consume,
        )

    def poll_kernel_stats(self) -> tuple[int, int]:
        # PACKET_STATISTICS resets on read, so each poll returns a delta.
        assert self._sock is not None
        data = self._sock.getsockopt(lp.SOL_PACKET, lp.PACKET_STATISTICS, 8)
        return lp.parse_tpacket_stats(data)

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()

"""Windows raw-IP capture adapter (SIO_RCVALL) — win32 only.

Delivers L3 headers without Ethernet framing; decode uses DLT_RAW.
Requires Administrator for SOCK_RAW + RCVALL.
"""

from __future__ import annotations

import contextlib
import socket

from .capture import CapturedHeader, CaptureSource, CaptureSourceConfig
from .config import CapturePointConfig, PolicyV2Config
from .decode import DLT_RAW
from .models import ObservedDirection
from .windows_packet import require_windows, resolve_bind_ipv4

# socket.SIO_RCVALL / RCVALL_ON exist on Windows CPython
_SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
_RCVALL_ON = getattr(socket, "RCVALL_ON", 1)
_RCVALL_OFF = getattr(socket, "RCVALL_OFF", 0)


def build_windows_raw_sources(config: PolicyV2Config, *, boot_id: str) -> tuple[CaptureSource, ...]:
    return tuple(
        CaptureSource(
            CaptureSourceConfig(sensor_id=config.sensor.id, capture_point=point, boot_id=boot_id),
            WindowsRawAdapter(point),
        )
        for point in config.sensor.capture_points
    )


class BytesHeaderReader:
    """HeaderReader over a complete IP datagram buffer."""

    __slots__ = ("_data", "wire_length")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.wire_length = len(data)

    def prefix(self, length: int) -> bytes:
        return self._data[:length]


class WindowsRawAdapter:
    """CaptureAdapter: raw IPv4 socket bound to one adapter address with SIO_RCVALL."""

    link_type = DLT_RAW

    def __init__(
        self,
        capture_point: CapturePointConfig,
        *,
        header_budget: int = 512,
        recv_timeout_seconds: float = 0.25,
    ) -> None:
        self._point = capture_point
        self._header_budget = header_budget
        self._recv_timeout = recv_timeout_seconds
        # Raw IP has no link-layer direction; honour a one-way capture point, else unknown.
        self._direction: ObservedDirection = (
            capture_point.direction if capture_point.direction != "both" else "unknown"
        )
        self._sock: socket.socket | None = None
        self._received = 0

    def open(self) -> str:
        require_windows()
        bind_ip = resolve_bind_ipv4(self._point.interface)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self._sock = sock
        sock.bind((bind_ip, 0))
        sock.ioctl(_SIO_RCVALL, _RCVALL_ON)
        sock.settimeout(self._recv_timeout)
        return f"windows-raw bind={bind_ip} interface={self._point.interface}"

    def read(self) -> CapturedHeader | None:
        assert self._sock is not None
        try:
            data = self._sock.recv(self._header_budget)
        except TimeoutError:
            return None
        if not data:
            return None
        self._received += 1
        return CapturedHeader(reader=BytesHeaderReader(data), direction=self._direction)

    def poll_kernel_stats(self) -> tuple[int, int]:
        # SIO_RCVALL exposes no drop counter; report datagrams received since last poll.
        received, self._received = self._received, 0
        return received, 0

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        with contextlib.suppress(OSError):
            sock.ioctl(_SIO_RCVALL, _RCVALL_OFF)
        with contextlib.suppress(OSError):
            sock.close()

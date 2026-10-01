"""Windows raw-IP capture adapter (SIO_RCVALL) — win32 only.

Delivers L3 headers without Ethernet framing; decode uses DLT_RAW.
Requires Administrator for SOCK_RAW + RCVALL.
"""

from __future__ import annotations

import contextlib
import ipaddress
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

    def __init__(self, data: bytes, *, wire_length: int | None = None) -> None:
        self._data = data
        self.wire_length = len(data) if wire_length is None else wire_length

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
        self._bind_ip: ipaddress.IPv4Address | None = None
        self._sock: socket.socket | None = None
        self._received = 0

    def open(self) -> str:
        require_windows()
        bind_ip = resolve_bind_ipv4(self._point.interface)
        self._bind_ip = ipaddress.IPv4Address(bind_ip)
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
        direction = self._packet_direction(data)
        if self._point.direction not in {"both", direction}:
            return None
        self._received += 1
        wire_length = int.from_bytes(data[2:4], "big") if len(data) >= 4 else len(data)
        return CapturedHeader(
            reader=BytesHeaderReader(data, wire_length=max(len(data), wire_length)),
            direction=direction,
        )

    def _packet_direction(self, data: bytes) -> ObservedDirection:
        if self._bind_ip is None or len(data) < 20 or data[0] >> 4 != 4:
            return "unknown"
        source = ipaddress.IPv4Address(data[12:16])
        destination = ipaddress.IPv4Address(data[16:20])
        if source == self._bind_ip:
            return "outbound"
        if destination == self._bind_ip:
            return "inbound"
        return "unknown"

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

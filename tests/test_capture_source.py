"""Shared live-capture lifecycle, driven through a scripted CaptureAdapter (any OS)."""

from __future__ import annotations

import ctypes
import socket
import struct
import threading
import time

import pytest
from packet_bytes import ipv4_packet, tcp_header

from ibn_monitor import linux_packet as lp
from ibn_monitor.capture import CapturedHeader, CaptureSource, CaptureSourceConfig
from ibn_monitor.capture_afpacket import AfPacketAdapter, pack_sock_fprog
from ibn_monitor.capture_windows import BytesHeaderReader, WindowsRawAdapter
from ibn_monitor.cbpf import build_filter
from ibn_monitor.config import CapturePointConfig
from ibn_monitor.decode import DLT_RAW

POINT = CapturePointConfig(name="lan", interface="eth0", direction="inbound", promiscuous=False)
PACKET = ipv4_packet(tcp_header(source_port=40000, destination_port=5432), protocol=6)


class ScriptedAdapter:
    """Replays a script per open(): each step is bytes, None (timeout), or an exception."""

    link_type = DLT_RAW

    def __init__(self, sessions: list[list[object] | Exception]) -> None:
        self._sessions = list(sessions)
        self._steps: list[object] = []
        self.opens = 0
        self.closes = 0
        self.released = 0
        self.kernel = (0, 0)
        self.drained = threading.Event()

    def open(self) -> str:
        self.opens += 1
        if not self._sessions:
            self.drained.set()
            raise RuntimeError("script exhausted")
        session = self._sessions.pop(0)
        if isinstance(session, Exception):
            raise session
        self._steps = list(session)
        return "scripted"

    def read(self) -> CapturedHeader | None:
        if not self._steps:
            self.drained.set()
            time.sleep(0.01)
            return None
        step = self._steps.pop(0)
        if isinstance(step, Exception):
            raise step
        if step is None:
            return None

        def release() -> None:
            self.released += 1

        return CapturedHeader(reader=BytesHeaderReader(step), direction="inbound", release=release)

    def poll_kernel_stats(self) -> tuple[int, int]:
        delta, self.kernel = self.kernel, (0, 0)
        return delta

    def close(self) -> None:
        self.closes += 1


def _run(adapter: ScriptedAdapter, **config) -> tuple[list, list]:
    source = CaptureSource(
        CaptureSourceConfig(
            sensor_id="s",
            capture_point=POINT,
            boot_id="b",
            reopen_backoff_initial_seconds=0.01,
            reopen_backoff_max_seconds=0.02,
            **config,
        ),
        adapter,
    )
    observations: list = []
    controls: list = []
    source.start(observations.append, controls.append)
    assert adapter.drained.wait(2)
    source.stop()
    return observations, controls


def test_decodes_headers_and_releases_each_one():
    adapter = ScriptedAdapter([[PACKET, None, PACKET]])
    observations, controls = _run(adapter)

    assert [o.destination_port for o in observations] == [5432, 5432]
    assert {o.source_generation for o in observations} == {"lan:b:1"}
    assert {o.direction for o in observations} == {"inbound"}
    assert adapter.released == 2
    kinds = [c.kind for c in controls]
    assert kinds[0] == "source_established"
    assert kinds[-1] == "source_stopped"


def test_decode_exception_falls_back_to_undecodable():
    class Exploding(BytesHeaderReader):
        def prefix(self, length: int) -> bytes:
            raise ValueError("boom")

    adapter = ScriptedAdapter([[PACKET]])
    adapter.read = lambda: (  # type: ignore[method-assign]
        adapter.drained.set() or CapturedHeader(reader=Exploding(PACKET), direction="unknown")
    )
    source = CaptureSource(
        CaptureSourceConfig(sensor_id="s", capture_point=POINT, boot_id="b"), adapter
    )
    observations: list = []
    source.start(observations.append, lambda _m: None)
    deadline = time.time() + 2
    while time.time() < deadline and not observations:
        time.sleep(0.01)
    source.stop()

    assert observations[0].outcome == "undecodable"
    assert observations[0].decode_reason == "decode_exception"
    assert observations[0].wire_length == len(PACKET)


def test_failure_retries_with_backoff_then_recovers_with_new_generation():
    adapter = ScriptedAdapter(
        [
            [PACKET, OSError("link down")],
            RuntimeError("still down"),
            [PACKET],
        ]
    )
    observations, controls = _run(adapter)

    kinds = [c.kind for c in controls if c.kind != "source_stats"]
    assert kinds[:6] == [
        "source_established",
        "source_failed",
        "source_retrying",
        "source_failed",
        "source_retrying",
        "source_recovered",
    ]
    assert controls[1].detail == "link down"
    assert [o.source_generation for o in observations] == ["lan:b:1", "lan:b:2"]
    assert adapter.closes >= adapter.opens - 1


def test_stats_accumulate_kernel_deltas_and_outcomes_even_when_idle():
    adapter = ScriptedAdapter([[PACKET, None, None]])
    adapter.kernel = (7, 2)
    _observations, controls = _run(adapter, stats_poll_interval_seconds=0.0)

    stats = [c.stats for c in controls if c.kind == "source_stats"]
    assert stats, "stats are emitted on idle timeouts too"
    last = stats[-1]
    assert (last.kernel_packets, last.kernel_drops) == (7, 2)
    assert (last.decode_complete, last.app_enqueue_ok, last.app_enqueue_drops) == (1, 1, 0)


def test_windows_adapter_reads_raw_datagrams_and_reports_received_count(monkeypatch):
    class FakeSocket:
        def __init__(self, *_args):
            self.reads = [PACKET, TimeoutError()]
            self.ioctls: list = []
            self.closed = False

        def bind(self, _addr):
            return

        def ioctl(self, *args):
            self.ioctls.append(args)

        def settimeout(self, _t):
            return

        def recv(self, _n):
            step = self.reads.pop(0)
            if isinstance(step, Exception):
                raise step
            return step

        def close(self):
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr("ibn_monitor.capture_windows.require_windows", lambda: None)
    monkeypatch.setattr("ibn_monitor.capture_windows.resolve_bind_ipv4", lambda _i: "192.168.1.10")
    monkeypatch.setattr("ibn_monitor.capture_windows.socket.socket", lambda *a: fake)
    adapter = WindowsRawAdapter(POINT)

    assert "192.168.1.10" in adapter.open()
    header = adapter.read()
    assert header is not None and header.direction == "inbound"
    assert header.reader.prefix(20) == PACKET[:20]
    assert adapter.read() is None
    assert adapter.poll_kernel_stats() == (1, 0)
    assert adapter.poll_kernel_stats() == (0, 0)
    adapter.close()
    adapter.close()
    assert fake.closed and len(fake.ioctls) == 2


def test_sock_fprog_points_at_the_packed_program():
    program = lp.sock_filter_program(build_filter(direction="inbound", snap_len=512))
    fprog, buffer = pack_sock_fprog(program)

    length, address = struct.unpack("HP", fprog)
    assert length == len(program) // 8
    assert address == ctypes.addressof(buffer)
    assert ctypes.string_at(address, len(program)) == program
    with pytest.raises(ValueError):
        pack_sock_fprog(b"\x00" * 7)


def test_afpacket_adapter_attaches_filter_and_peeks(monkeypatch):
    class FakePacketSocket:
        def __init__(self, *_args):
            self.options: dict = {}
            self.recv_calls: list = []

        def bind(self, _addr):
            return

        def setsockopt(self, level, name, value):
            if name == 26:
                length, address = struct.unpack("HP", value)
                value = ctypes.string_at(address, length * 8)
            self.options[(level, name)] = value

        def settimeout(self, _t):
            return

        def recv(self, length, flags=0):
            self.recv_calls.append((length, flags))
            return PACKET[:length]

        def close(self):
            return

    fake = FakePacketSocket()
    monkeypatch.setattr(lp, "require_linux", lambda: None)
    monkeypatch.setattr("ibn_monitor.capture_afpacket.socket.if_nametoindex", lambda _i: 3)
    monkeypatch.setattr("ibn_monitor.capture_afpacket.socket.socket", lambda *a: fake)
    adapter = AfPacketAdapter(POINT)

    assert "cbpf=on" in adapter.open()
    expected = lp.sock_filter_program(build_filter(direction="inbound", snap_len=512))
    assert fake.options[(socket.SOL_SOCKET, 26)] == expected
    header = adapter.read()
    assert header is not None and header.release is not None
    header.release()
    assert fake.recv_calls[0][1] == 0x2  # MSG_PEEK
    assert fake.recv_calls[-1][1] == 0  # consume

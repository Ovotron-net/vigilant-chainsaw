import sys
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from packet_bytes import icmp_header, ipv4_packet, tcp_header

from ibn_monitor.capture_windows import (
    WindowsRawSource,
    WindowsRawSourceConfig,
    _BytesHeaderReader,
)
from ibn_monitor.config import CapturePointConfig
from ibn_monitor.decode import DLT_RAW, ObservationContext, decode_observation
from ibn_monitor.windows_packet import AdapterAddress, resolve_bind_ipv4


def test_bytes_header_reader_and_dlt_raw_decode():
    frame = ipv4_packet(tcp_header(source_port=40000, destination_port=5432), protocol=6)
    reader = _BytesHeaderReader(frame)
    ctx = ObservationContext(
        captured_at=datetime(2026, 7, 24, tzinfo=UTC),
        monotonic_at=1.0,
        sensor_id="win-1",
        source_generation="g1",
        capture_point="lan",
        interface="auto",
        direction="unknown",
    )
    obs = decode_observation(reader, DLT_RAW, ctx)
    assert obs.outcome == "complete"
    assert obs.destination_port == 5432
    assert str(obs.source).endswith("1") or obs.source is not None


def test_resolve_bind_ipv4_literal(monkeypatch):
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.require_windows", lambda: None
    )
    assert resolve_bind_ipv4("10.0.0.5") == "10.0.0.5"


def test_resolve_bind_ipv4_auto(monkeypatch):
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.require_windows", lambda: None
    )
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.list_ipv4_adapters",
        lambda: [
            AdapterAddress("lo", "Loopback", "127.0.0.1", True),
            AdapterAddress("{guid}", "Ethernet", "192.168.1.10", True),
        ],
    )
    assert resolve_bind_ipv4("auto") == "192.168.1.10"
    assert resolve_bind_ipv4("Ethernet") == "192.168.1.10"


def test_resolve_unknown_interface(monkeypatch):
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.require_windows", lambda: None
    )
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.list_ipv4_adapters",
        lambda: [AdapterAddress("{g}", "Ethernet", "192.168.1.10", True)],
    )
    with pytest.raises(RuntimeError, match="not found"):
        resolve_bind_ipv4("no-such-nic")


@pytest.mark.skipif(sys.platform != "win32", reason="WindowsRawSource is win32-only")
def test_windows_raw_source_requires_admin_or_fails_clean():
    """Construction succeeds; start may fail without admin — no crash on init."""
    point = CapturePointConfig(
        name="lan",
        interface="auto",
        direction="both",
        promiscuous=False,
    )
    src = WindowsRawSource(
        WindowsRawSourceConfig(
            sensor_id="s",
            capture_point=point,
            boot_id="b",
        )
    )
    assert src.capture_point == "lan"


def test_windows_source_recv_path_with_fake_socket(monkeypatch):
    monkeypatch.setattr(
        "ibn_monitor.capture_windows.require_windows", lambda: None
    )
    monkeypatch.setattr(
        "ibn_monitor.capture_windows.resolve_bind_ipv4", lambda _i: "192.168.1.10"
    )
    monkeypatch.setattr(
        "ibn_monitor.capture_windows.sys.platform", "win32", raising=False
    )

    packet = ipv4_packet(icmp_header(), protocol=1)
    sock = MagicMock()
    # First recv returns packet, then raise so loop can stop via _stop
    calls = {"n": 0}

    def recv(_n):
        calls["n"] += 1
        if calls["n"] == 1:
            return packet
        raise TimeoutError

    sock.recv.side_effect = recv
    sock.ioctl = MagicMock()
    sock.settimeout = MagicMock()
    sock.bind = MagicMock()
    sock.close = MagicMock()

    monkeypatch.setattr(
        "ibn_monitor.capture_windows.socket.socket", lambda *a, **k: sock
    )

    point = CapturePointConfig(
        name="lan",
        interface="auto",
        direction="both",
        promiscuous=False,
    )
    # Bypass platform check in __init__
    src = object.__new__(WindowsRawSource)
    src._config = WindowsRawSourceConfig(
        sensor_id="s", capture_point=point, boot_id="b"
    )
    src._thread = None
    src._stop = __import__("threading").Event()
    src._observation_sink = None
    src._control_sink = None
    src._generation_counter = 0
    src._source_generation = None
    src._kernel_packets = 0
    src._kernel_drops = 0
    src._app_ok = 0
    src._app_drops = 0
    src._decode_complete = 0
    src._decode_partial = 0
    src._decode_undecodable = 0
    src._bind_ipv4 = None

    observations = []
    controls = []
    src.start(observations.append, controls.append)
    # Allow thread to process one packet
    import time

    deadline = time.time() + 2
    while time.time() < deadline and not observations:
        time.sleep(0.05)
    src.stop()

    assert any(c.kind == "source_established" for c in controls)
    assert observations, "expected at least one decoded observation"
    assert observations[0].outcome in {"complete", "partial", "undecodable"}

from datetime import UTC, datetime

import pytest
from packet_bytes import ipv4_packet, tcp_header

from ibn_monitor.capture_windows import BytesHeaderReader
from ibn_monitor.decode import DLT_RAW, ObservationContext, decode_observation
from ibn_monitor.windows_packet import AdapterAddress, resolve_bind_ipv4


def test_bytes_header_reader_and_dlt_raw_decode():
    frame = ipv4_packet(tcp_header(source_port=40000, destination_port=5432), protocol=6)
    reader = BytesHeaderReader(frame)
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
    monkeypatch.setattr("ibn_monitor.windows_packet.require_windows", lambda: None)
    assert resolve_bind_ipv4("10.0.0.5") == "10.0.0.5"


def test_resolve_bind_ipv4_auto(monkeypatch):
    monkeypatch.setattr("ibn_monitor.windows_packet.require_windows", lambda: None)
    monkeypatch.setattr("ibn_monitor.windows_packet.default_route_ipv4", lambda: None)
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.list_ipv4_adapters",
        lambda: [
            AdapterAddress("lo", "Loopback", "127.0.0.1", True),
            AdapterAddress("{guid}", "Ethernet", "192.168.1.10", True),
        ],
    )
    assert resolve_bind_ipv4("auto") == "192.168.1.10"
    assert resolve_bind_ipv4("Ethernet") == "192.168.1.10"


ADAPTERS = [
    AdapterAddress("{ts}", "Tailscale", "169.254.83.107", True),
    AdapterAddress("{eth}", "Ethernet 3", "192.168.50.117", True),
    AdapterAddress("{wifi}", "Wi-Fi", "192.168.50.181", True),
]


@pytest.mark.parametrize(
    ("default_route", "expected"),
    [
        ("192.168.50.181", "192.168.50.181"),  # follows the default route
        (None, "192.168.50.117"),  # no route: first routable, never link-local
        ("10.9.9.9", "192.168.50.117"),  # route via an unknown/down adapter is ignored
    ],
)
def test_resolve_auto_prefers_default_route_and_skips_link_local(
    monkeypatch, default_route, expected
):
    monkeypatch.setattr("ibn_monitor.windows_packet.require_windows", lambda: None)
    monkeypatch.setattr("ibn_monitor.windows_packet.list_ipv4_adapters", lambda: ADAPTERS)
    monkeypatch.setattr("ibn_monitor.windows_packet.default_route_ipv4", lambda: default_route)
    assert resolve_bind_ipv4("auto") == expected


def test_resolve_auto_rejects_only_link_local(monkeypatch):
    monkeypatch.setattr("ibn_monitor.windows_packet.require_windows", lambda: None)
    monkeypatch.setattr("ibn_monitor.windows_packet.list_ipv4_adapters", lambda: ADAPTERS[:1])
    monkeypatch.setattr("ibn_monitor.windows_packet.default_route_ipv4", lambda: None)
    with pytest.raises(RuntimeError, match="routable"):
        resolve_bind_ipv4("auto")


def test_resolve_unknown_interface(monkeypatch):
    monkeypatch.setattr("ibn_monitor.windows_packet.require_windows", lambda: None)
    monkeypatch.setattr(
        "ibn_monitor.windows_packet.list_ipv4_adapters",
        lambda: [AdapterAddress("{g}", "Ethernet", "192.168.1.10", True)],
    )
    with pytest.raises(RuntimeError, match="not found"):
        resolve_bind_ipv4("no-such-nic")

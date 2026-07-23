"""Property/fuzz-style tests: decoder never raises and stays payload-safe."""

from __future__ import annotations

import os
import random
from datetime import UTC, datetime

import pytest
from packet_bytes import ETHERNET, RAW, ethernet_frame, ipv4_packet, tcp_header

from ibn_monitor.decode import ObservationContext, decode_observation


class PrefixReader:
    def __init__(self, data: bytes, wire_length: int | None = None):
        self.data = data
        self.wire_length = wire_length if wire_length is not None else len(data)
        self.max_requested = 0

    def prefix(self, length: int) -> bytes:
        self.max_requested = max(self.max_requested, length)
        return self.data[:length]


def _context():
    return ObservationContext(
        captured_at=datetime(2026, 7, 24, tzinfo=UTC),
        monotonic_at=None,
        sensor_id="fuzz",
        source_generation="g",
        capture_point="pcap",
        interface=None,
        direction="unknown",
    )


@pytest.mark.parametrize("seed", range(32))
def test_random_bytes_never_raise(seed: int):
    rng = random.Random(seed)
    blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 800)))
    reader = PrefixReader(blob, wire_length=len(blob) + rng.randint(0, 200))
    result = decode_observation(reader, ETHERNET, _context())
    assert result.outcome in {"complete", "partial", "undecodable"}
    assert reader.max_requested <= 512


def test_payload_not_required_for_tcp_decode():
    headers = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    secret = b"SECRET_PAYLOAD_SHOULD_NOT_BE_READ"
    reader = PrefixReader(headers + secret, wire_length=1500)
    result = decode_observation(reader, ETHERNET, _context())
    assert result.protocol == "tcp"
    assert result.destination_port == 5432
    assert reader.max_requested == len(headers)
    assert secret not in reader.data[: reader.max_requested]


@pytest.mark.parametrize("datalink", [ETHERNET, RAW, 113, 276, 0, 999])
def test_datalink_variants_do_not_raise(datalink: int):
    data = os.urandom(128)
    result = decode_observation(PrefixReader(data), datalink, _context())
    assert result.outcome in {"complete", "partial", "undecodable"}

from datetime import UTC, datetime

import pytest
from packet_bytes import (
    ETHERNET,
    ethernet_frame,
    icmp_header,
    ipv4_packet,
    ipv6_fragment,
    ipv6_options,
    ipv6_packet,
    tcp_header,
    udp_header,
)

from ibn_monitor.decode import ObservationContext, decode_observation


class TrackingReader:
    def __init__(self, data, wire_length=None):
        self.data = data
        self.wire_length = wire_length or len(data)
        self.requests = []

    def prefix(self, length):
        self.requests.append(length)
        return self.data[:length]


def context():
    return ObservationContext(
        captured_at=datetime(2026, 7, 23, tzinfo=UTC),
        monotonic_at=None,
        sensor_id="sensor-1",
        source_generation="replay-0",
        capture_point="pcap",
        interface=None,
        direction="unknown",
    )


def test_decodes_ethernet_ipv4_tcp_without_requesting_payload():
    headers = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    reader = TrackingReader(headers + b"secret payload", wire_length=1500)
    result = decode_observation(reader, ETHERNET, context())
    assert result.protocol == "tcp"
    assert result.destination_port == 5432
    assert result.wire_length == 1500
    assert max(reader.requests) == len(headers)


def test_decodes_two_vlan_tags_and_udp():
    headers = ethernet_frame(
        ipv4_packet(udp_header(), protocol=17),
        ethertype=0x0800,
        vlan_types=(0x88A8, 0x8100),
    )
    result = decode_observation(TrackingReader(headers), ETHERNET, context())
    assert result.protocol == "udp"
    assert result.destination_port == 53


def test_non_initial_fragment_is_partial_but_keeps_endpoints():
    frame = ethernet_frame(ipv4_packet(b"", protocol=6, fragment=1))
    result = decode_observation(TrackingReader(frame), ETHERNET, context())
    assert result.outcome == "partial"
    assert result.decode_reason == "non_initial_fragment"
    assert result.source is not None
    assert result.destination_port is None


def test_short_ipv4_total_length_is_partial():
    # IPv4 total length too short for TCP header: 20 (IP) + 8 < 40 needed for TCP.
    payload = tcp_header()
    packet = bytearray(ipv4_packet(payload, protocol=6))
    packet[2:4] = (20 + 8).to_bytes(2, "big")
    frame = ethernet_frame(bytes(packet))
    result = decode_observation(TrackingReader(frame), ETHERNET, context())
    assert result.outcome == "partial"
    assert result.decode_reason == "header_exceeds_ip_length"
    assert result.source is not None


def test_decodes_icmpv6_after_hop_by_hop_header():
    packet = ipv6_packet(
        ipv6_options(58) + icmp_header(),
        next_header=0,
    )
    result = decode_observation(TrackingReader(packet), 101, context())
    assert result.ip_version == 6
    assert result.protocol == "icmp"
    assert result.icmp_type == 128
    assert result.icmp_code == 0


def test_non_initial_ipv6_fragment_is_partial():
    packet = ipv6_packet(
        ipv6_fragment(17, offset=1) + b"\x00" * 8,
        next_header=44,
    )
    result = decode_observation(TrackingReader(packet), 101, context())
    assert result.outcome == "partial"
    assert result.decode_reason == "non_initial_fragment"
    assert result.destination_port is None


def test_ipv6_extension_count_is_bounded():
    payload = udp_header()
    next_header = 17
    for _ in range(9):
        payload = ipv6_options(next_header) + payload
        next_header = 0
    result = decode_observation(
        TrackingReader(ipv6_packet(payload, next_header=0)),
        101,
        context(),
    )
    assert result.outcome == "partial"
    assert result.decode_reason == "ipv6_extension_count_limit"


def struct_pack_tcp_bad_offset():
    import struct

    return struct.pack(
        "!HHIIBBHHH",
        40000,
        5432,
        0,
        0,
        3 << 4,  # data offset 3 * 4 = 12 < 20
        0x02,
        8192,
        0,
        0,
    )


@pytest.mark.parametrize(
    ("frame", "datalink", "reason"),
    [
        (
            ethernet_frame(bytes([0x44]) + b"\x00" * 19),
            ETHERNET,
            "invalid_ipv4_ihl",
        ),
        (
            ethernet_frame(bytes([0x45, 0, 0, 10]) + b"\x00" * 16),
            ETHERNET,
            "invalid_ipv4_total_length",
        ),
        (
            ethernet_frame(ipv4_packet(struct_pack_tcp_bad_offset(), protocol=6)),
            ETHERNET,
            "invalid_tcp_data_offset",
        ),
        (
            ethernet_frame(ipv4_packet(b"\x00" * 4, protocol=17)),
            ETHERNET,
            "header_exceeds_ip_length",
        ),
        (
            ipv6_packet(b"", next_header=17),
            101,
            "ipv6_jumbogram_unsupported",
        ),
        (
            ethernet_frame(
                b"\x00" * 14, ethertype=0x0800, vlan_types=(0x8100, 0x8100, 0x8100)
            ),
            ETHERNET,
            "vlan_depth_limit",
        ),
        (
            b"\x00" * 20,
            105,
            "unsupported_datalink",
        ),
    ],
)
def test_malformed_length_regressions(frame, datalink, reason):
    result = decode_observation(TrackingReader(frame), datalink, context())
    assert result.outcome in {"partial", "undecodable"}
    assert result.decode_reason == reason

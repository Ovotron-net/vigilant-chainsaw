#!/usr/bin/env python3
"""Generate a deterministic classic-PCAP fixture without Scapy."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


def tcp_header(source_port: int, destination_port: int, flags: int = 0x02) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )


def ipv4_packet(payload: bytes, protocol: int, source: str, destination: str) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return header + payload


def ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00" * 12 + struct.pack("!H", ethertype) + payload


def classic_pcap(records: list[tuple[int, int, bytes, int]]) -> bytes:
    output = bytearray(b"\xd4\xc3\xb2\xa1")
    output.extend(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for seconds, fraction, frame, wire_length in records:
        output.extend(struct.pack("<IIII", seconds, fraction, len(frame), wire_length))
        output.extend(frame)
    return bytes(output)


def main() -> None:
    match = ethernet_frame(
        ipv4_packet(
            tcp_header(50000, 5432),
            protocol=6,
            source="10.20.5.14",
            destination="10.50.10.8",
        )
    )
    allowed = ethernet_frame(
        ipv4_packet(
            tcp_header(50001, 443),
            protocol=6,
            source="10.20.5.14",
            destination="10.50.10.8",
        )
    )
    payload = classic_pcap(
        [
            (1_700_000_000, 0, match, len(match)),
            (1_700_000_001, 0, allowed, len(allowed)),
        ]
    )
    output = Path("test-traffic.pcap")
    output.write_bytes(payload)
    print(output)


if __name__ == "__main__":
    main()

import ipaddress
import struct

ETHERNET = 1
RAW = 101
LINUX_SLL = 113
LINUX_SLL2 = 276


def tcp_header(source_port=40000, destination_port=5432, flags=0x02):
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


def udp_header(source_port=40000, destination_port=53):
    return struct.pack("!HHHH", source_port, destination_port, 8, 0)


def ipv4_packet(payload, protocol, source="10.20.5.14", destination="10.50.10.8", fragment=0):
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        fragment,
        64,
        protocol,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return header + payload


def ethernet_frame(payload, ethertype=0x0800, vlan_types=()):
    frame = b"\x00" * 12
    for vlan_type in vlan_types:
        frame += struct.pack("!HH", vlan_type, 1)
    return frame + struct.pack("!H", ethertype) + payload


def ipv6_packet(
    payload,
    next_header,
    source="2001:db8::1",
    destination="2001:db8::2",
):
    version_flow = 6 << 28
    header = struct.pack(
        "!IHBB16s16s",
        version_flow,
        len(payload),
        next_header,
        64,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return header + payload


def ipv6_options(next_header, payload=b""):
    padded = payload + b"\x00" * ((6 - len(payload)) % 8)
    return bytes([next_header, len(padded) // 8]) + padded


def ipv6_fragment(next_header, offset=0, more=False):
    offset_flags = (offset << 3) | int(more)
    return struct.pack("!BBHI", next_header, 0, offset_flags, 1)


def icmp_header(type_=128, code=0):
    return bytes([type_, code]) + b"\x00" * 6

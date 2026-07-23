"""Linux AF_PACKET helpers. Import only on Linux live path."""

from __future__ import annotations

import struct
import sys
from typing import Any

# packet(7) constants
AF_PACKET = 17
SOCK_RAW = 3
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_AUXDATA = 8
PACKET_STATISTICS = 6
PACKET_HOST = 0
PACKET_OUTGOING = 4
ARPHRD_ETHER = 1

# if.h flags
IFF_UP = 0x1
IFF_RUNNING = 0x40


def require_linux() -> None:
    if sys.platform != "linux":
        raise RuntimeError("AF_PACKET helpers require Linux")


def map_packet_type(pkttype: int) -> str:
    if pkttype == PACKET_OUTGOING:
        return "outbound"
    return "inbound"


def parse_tpacket_stats(data: bytes) -> tuple[int, int]:
    """Return (tp_packets, tp_drops) from PACKET_STATISTICS blob."""
    if len(data) < 8:
        return 0, 0
    packets, drops = struct.unpack("II", data[:8])
    return packets, drops


def htons(value: int) -> int:
    return struct.unpack("!H", struct.pack("H", value))[0]


def build_packet_mreq(ifindex: int, mr_type: int = PACKET_MR_PROMISC) -> bytes:
    # struct packet_mreq
    return struct.pack("iHH8s", ifindex, mr_type, 0, b"\x00" * 8)


def sock_filter_program(insns: list[tuple[int, int, int, int]]) -> Any:
    """Pack classic BPF for SO_ATTACH_FILTER (len + pointer handled by caller)."""
    # struct sock_filter { uint16 code; uint8 jt; uint8 jf; uint32 k; }
    return b"".join(struct.pack("HBBI", code, jt, jf, k & 0xFFFFFFFF) for code, jt, jf, k in insns)

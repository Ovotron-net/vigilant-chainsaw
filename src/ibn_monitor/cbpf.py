"""Owned classic-BPF templates for AF_PACKET (no free-form operator BPF)."""

from __future__ import annotations

from typing import Literal

CaptureDirection = Literal["inbound", "outbound", "both"]

PACKET_HOST = 0
PACKET_BROADCAST = 1
PACKET_MULTICAST = 2
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4

SKF_AD_OFF = -0x1000
SKF_AD_PKTTYPE = 4

BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_H = 0x08
BPF_B = 0x10
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K = 0x00

VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

BpfInsn = tuple[int, int, int, int]


def _ld_b_abs(k: int) -> BpfInsn:
    return (BPF_LD | BPF_B | BPF_ABS, 0, 0, k & 0xFFFFFFFF)


def _ld_h_abs(k: int) -> BpfInsn:
    return (BPF_LD | BPF_H | BPF_ABS, 0, 0, k & 0xFFFFFFFF)


def _jeq(k: int, jt: int, jf: int) -> BpfInsn:
    return (BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k & 0xFFFFFFFF)


def _ret(k: int) -> BpfInsn:
    return (BPF_RET | BPF_K, 0, 0, k & 0xFFFFFFFF)


def build_filter(
    *,
    direction: CaptureDirection,
    snap_len: int = 512,
) -> list[BpfInsn]:
    """Return classic BPF instructions as (code, jt, jf, k) tuples."""
    if not 1 <= snap_len <= 512:
        raise ValueError("snap_len must be in 1..512")

    prog: list[BpfInsn] = [_ld_b_abs(SKF_AD_OFF + SKF_AD_PKTTYPE)]
    if direction == "inbound":
        prog.append(_jeq(PACKET_OUTGOING, 0, 1))
        prog.append(_ret(0))
    elif direction == "outbound":
        prog.append(_jeq(PACKET_OUTGOING, 1, 0))
        prog.append(_ret(0))

    prog.append(_ld_h_abs(12))
    prog.append(_jeq(ETHERTYPE_IPV4, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_jeq(ETHERTYPE_IPV6, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_jeq(0x8100, 3, 0))
    prog.append(_jeq(0x88A8, 2, 0))
    prog.append(_jeq(0x9100, 1, 0))
    prog.append(_ret(0))
    prog.append(_ld_h_abs(16))
    prog.append(_jeq(ETHERTYPE_IPV4, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_jeq(ETHERTYPE_IPV6, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_jeq(0x8100, 3, 0))
    prog.append(_jeq(0x88A8, 2, 0))
    prog.append(_jeq(0x9100, 1, 0))
    prog.append(_ret(0))
    prog.append(_ld_h_abs(20))
    prog.append(_jeq(ETHERTYPE_IPV4, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_jeq(ETHERTYPE_IPV6, 0, 1))
    prog.append(_ret(snap_len))
    prog.append(_ret(0))
    return prog

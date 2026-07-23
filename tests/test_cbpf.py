from ibn_monitor.cbpf import (
    ETHERTYPE_IPV4,
    PACKET_OUTGOING,
    SKF_AD_OFF,
    SKF_AD_PKTTYPE,
    build_filter,
)


def test_build_filter_loads_packet_type_ancillary():
    prog = build_filter(direction="inbound", snap_len=512)
    assert prog[0][3] == (SKF_AD_OFF + SKF_AD_PKTTYPE) & 0xFFFFFFFF


def test_inbound_rejects_outgoing_constant():
    prog = build_filter(direction="inbound", snap_len=128)
    # Second instruction compares OUTGOING
    assert any(insn[3] == PACKET_OUTGOING for insn in prog[:4])


def test_accepts_ipv4_ret_snap():
    prog = build_filter(direction="both", snap_len=256)
    assert any(insn[3] == ETHERTYPE_IPV4 for insn in prog)
    assert any(insn[0] & 0x07 == 0x06 and insn[3] == 256 for insn in prog)


def test_snap_len_bounds():
    import pytest

    with pytest.raises(ValueError):
        build_filter(direction="both", snap_len=0)

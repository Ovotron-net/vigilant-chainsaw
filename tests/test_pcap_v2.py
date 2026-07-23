from io import BytesIO

import pytest
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from pcap_bytes import classic_pcap
from test_decode_v2 import context

from ibn_monitor.pcap import PcapError, iter_pcap_stream


class TrackingStream(BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.read_ranges = []

    def read(self, size=-1):
        start = self.tell()
        data = super().read(size)
        self.read_ranges.append((start, len(data)))
        return data


@pytest.mark.parametrize(("endian", "nanosecond"), [("<", False), (">", True)])
def test_streams_timestamped_observations(endian, nanosecond):
    frame = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    fraction = 500_000_000 if nanosecond else 500_000
    stream = TrackingStream(
        classic_pcap(
            [(1_700_000_000, fraction, frame + b"secret", 1500)],
            endian=endian,
            nanosecond=nanosecond,
        )
    )
    observations = list(iter_pcap_stream(stream, context=context()))
    assert observations[0].captured_at.microsecond == 500_000
    assert observations[0].wire_length == 1500
    packet_start = 24 + 16
    packet_bytes_read = sum(
        length for start, length in stream.read_ranges if start >= packet_start
    )
    assert packet_bytes_read == len(frame)
    assert stream.tell() == len(stream.getvalue())


def test_rejects_pcapng_before_records():
    with pytest.raises(PcapError, match="PCAPNG is not supported"):
        list(
            iter_pcap_stream(
                BytesIO(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20), context=context()
            )
        )


def test_rejects_unsupported_datalink_before_records():
    payload = classic_pcap([], datalink=105)
    with pytest.raises(PcapError, match="unsupported datalink 105"):
        list(iter_pcap_stream(BytesIO(payload), context=context()))

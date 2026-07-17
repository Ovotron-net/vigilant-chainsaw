import threading

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import wrpcap

import ibn_monitor.capture as capture
from ibn_monitor.capture import PcapReplaySource, ScapyLiveSource, packet_to_metadata
from ibn_monitor.config import SensorConfig


def test_decodes_ipv4_tcp_packet():
    metadata = packet_to_metadata(IP(src="10.20.5.14", dst="10.50.10.8") / TCP(dport=5432))
    assert metadata is not None
    assert metadata.protocol == "tcp"
    assert metadata.destination_port == 5432


def test_decodes_ipv6_udp_packet():
    metadata = packet_to_metadata(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(dport=53))
    assert metadata is not None
    assert metadata.protocol == "udp"
    assert metadata.destination_port == 53


def test_undecodable_packet_yields_none():
    assert packet_to_metadata(TCP(dport=80)) is None


def test_pcap_replay_source_pushes_metadata(tmp_path):
    pcap = tmp_path / "flows.pcap"
    wrpcap(
        str(pcap),
        [
            IP(src="10.20.5.14", dst="10.50.10.8") / TCP(dport=5432),
            IP(src="10.20.5.14", dst="10.50.10.9") / UDP(dport=53),
        ],
    )

    received = []
    source = PcapReplaySource(pcap)
    source.start(received.append)  # finite source: blocks until EOF
    source.stop()

    assert [meta.protocol for meta in received] == ["tcp", "udp"]
    assert received[0].destination_port == 5432


def test_live_source_waits_until_capture_is_established(monkeypatch):
    release_startup = threading.Event()
    received = []

    class FakeAsyncSniffer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.thread = None

        def start(self):
            def run():
                release_startup.wait()
                self.running = True
                self.kwargs["prn"](
                    IP(src="10.20.5.14", dst="10.50.10.8") / TCP(dport=5432)
                )
                self.kwargs["started_callback"]()

            self.thread = threading.Thread(target=run)
            self.thread.start()

        def join(self):
            self.thread.join()

        def stop(self, *, join):
            self.running = False
            if join:
                self.thread.join()

    monkeypatch.setattr(capture, "AsyncSniffer", FakeAsyncSniffer)
    source = ScapyLiveSource(SensorConfig(interface="eth0", bpf_filter="tcp", promiscuous=True))
    start_thread = threading.Thread(target=source.start, args=(received.append,))
    start_thread.start()

    assert start_thread.is_alive()
    release_startup.set()
    start_thread.join(timeout=1)
    source.stop()

    assert not start_thread.is_alive()
    assert received[0].destination_port == 5432


def test_live_source_propagates_startup_failure(monkeypatch):
    class FailingAsyncSniffer:
        def __init__(self, **kwargs):
            self.exception = PermissionError("capture denied")
            self.running = False
            self.thread = None

        def start(self):
            self.thread = threading.Thread(target=lambda: None)
            self.thread.start()
            self.thread.join()

        def join(self):
            raise self.exception

    monkeypatch.setattr(capture, "AsyncSniffer", FailingAsyncSniffer)
    source = ScapyLiveSource(SensorConfig(interface=None, bpf_filter="", promiscuous=False))

    with pytest.raises(PermissionError, match="capture denied"):
        source.start(lambda _: None)

    source.stop()


def test_pcap_replay_stop_prevents_further_delivery(monkeypatch):
    before_second_packet = threading.Event()
    continue_replay = threading.Event()
    packets = [
        IP(src="10.20.5.14", dst="10.50.10.8") / TCP(dport=5432),
        IP(src="10.20.5.14", dst="10.50.10.9") / UDP(dport=53),
    ]

    def fake_sniff(*, prn, stop_filter, **kwargs):
        prn(packets[0])
        if stop_filter(packets[0]):
            return
        before_second_packet.set()
        continue_replay.wait()
        prn(packets[1])
        stop_filter(packets[1])

    monkeypatch.setattr(capture, "sniff", fake_sniff)
    source = PcapReplaySource("flows.pcap")
    received = []
    replay_thread = threading.Thread(target=source.start, args=(received.append,))
    replay_thread.start()
    assert before_second_packet.wait(timeout=1)

    source.stop()
    continue_replay.set()
    replay_thread.join(timeout=1)

    assert not replay_thread.is_alive()
    assert [meta.destination_port for meta in received] == [5432]

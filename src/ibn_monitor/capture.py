"""Packet capture seam: one PacketSource interface, one adapter per packet origin.

All Scapy imports live here so the rest of the codebase never touches raw packets.
Sources push ``PacketMetadata | None`` (``None`` = undecodable packet) to a callback.
Contract: ``start()`` returns once capture is established (live sources) or the
source is exhausted (finite sources such as PCAP replay).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from scapy.config import conf

from .config import SensorConfig
from .models import ControlMessage, Observation, PacketMetadata, SourceStatsSnapshot

# Route discovery is unnecessary for passive capture and can fail in restricted containers.
conf.route_autoload = False
conf.route6_autoload = False

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.sendrecv import AsyncSniffer, sniff  # noqa: E402

PacketCallback = Callable[[PacketMetadata | None], None]
ObservationSink = Callable[[Observation], None]
ControlSink = Callable[[ControlMessage], None]


class PacketSource(Protocol):
    """Seam between packet capture and the monitor loop."""

    def start(
        self, callback: PacketCallback, *, on_established: Callable[[], None] | None = None
    ) -> None:
        """Begin delivering packets to ``callback``.

        Returns once capture is established (live) or the source is
        exhausted (finite). ``on_established`` is invoked once capture is
        confirmed established, before any packet delivery.
        """
        ...

    def stop(self) -> None:
        """Stop delivering packets. Idempotent."""
        ...


class ObservationSource(Protocol):
    """V2 live capture seam: one logical capture point (or test double)."""

    @property
    def capture_point(self) -> str: ...

    def start(
        self,
        observation_sink: ObservationSink,
        control_sink: ControlSink,
    ) -> None: ...

    def stop(self) -> None: ...


class MemoryObservationSource:
    """In-memory ObservationSource for pure tests."""

    def __init__(self, capture_point: str, *, auto_establish: bool = True) -> None:
        self._capture_point = capture_point
        self._auto_establish = auto_establish
        self._observation_sink: ObservationSink | None = None
        self._control_sink: ControlSink | None = None
        self._generation = f"{capture_point}:test:1"

    @property
    def capture_point(self) -> str:
        return self._capture_point

    def start(
        self,
        observation_sink: ObservationSink,
        control_sink: ControlSink,
    ) -> None:
        self._observation_sink = observation_sink
        self._control_sink = control_sink
        if self._auto_establish:
            self.emit_established(self._generation)

    def stop(self) -> None:
        if self._control_sink is not None:
            self._control_sink(
                ControlMessage(
                    kind="source_stopped",
                    monotonic_at=0.0,
                    capture_point=self._capture_point,
                    source_generation=self._generation,
                )
            )

    def push(self, observation: Observation) -> None:
        if self._observation_sink is None:
            raise RuntimeError("source not started")
        self._observation_sink(observation)

    def emit_failed(self, reason: str) -> None:
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_failed",
                monotonic_at=0.0,
                capture_point=self._capture_point,
                detail=reason,
            )
        )

    def emit_stats(self, stats: SourceStatsSnapshot) -> None:
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_stats",
                monotonic_at=0.0,
                capture_point=stats.capture_point,
                source_generation=stats.source_generation,
                stats=stats,
            )
        )

    def emit_established(self, source_generation: str) -> None:
        self._generation = source_generation
        if self._control_sink is None:
            raise RuntimeError("source not started")
        self._control_sink(
            ControlMessage(
                kind="source_established",
                monotonic_at=0.0,
                capture_point=self._capture_point,
                source_generation=source_generation,
            )
        )


class ScapyLiveSource:
    """Live capture adapter backed by Scapy's AsyncSniffer."""

    def __init__(self, sensor: SensorConfig) -> None:
        self._sensor = sensor
        self._sniffer: AsyncSniffer | None = None

    def start(
        self, callback: PacketCallback, *, on_established: Callable[[], None] | None = None
    ) -> None:
        started = Event()
        self._sniffer = AsyncSniffer(
            iface=self._sensor.interface,
            filter=self._sensor.bpf_filter,
            promisc=self._sensor.promiscuous,
            prn=lambda packet: callback(packet_to_metadata(packet)),
            started_callback=started.set,
            store=False,
        )
        self._sniffer.start()
        while not started.wait(0.01):
            thread = self._sniffer.thread
            if thread is not None and not thread.is_alive():
                self._sniffer.join()
                raise RuntimeError("Live packet capture stopped before startup completed")
        if on_established is not None:
            on_established()

    def stop(self) -> None:
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop(join=True)
        self._sniffer = None


class PcapReplaySource:
    """Finite adapter that replays a PCAP file; ``start()`` blocks until EOF."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._stop_requested = Event()

    def start(
        self, callback: PacketCallback, *, on_established: Callable[[], None] | None = None
    ) -> None:
        self._stop_requested.clear()
        if on_established is not None:
            on_established()

        def deliver(packet: Any) -> None:
            if not self._stop_requested.is_set():
                callback(packet_to_metadata(packet))

        sniff(
            offline=self._path,
            prn=deliver,
            stop_filter=lambda _: self._stop_requested.is_set(),
            store=False,
        )

    def stop(self) -> None:
        self._stop_requested.set()


# IPv6 extension headers that can sit between the IPv6 header and ICMPv6 (RFC 8200).
_IPV6_EXTENSION_HEADERS = frozenset(
    {0, 43, 44, 51, 60}  # hop-by-hop, routing, fragment, authentication, dst opts
)
_ICMPV6_PROTOCOL_NUMBER = 58


def _ipv6_carries_icmpv6(ipv6_layer: Any) -> bool:
    """Follow the next-header chain through extension headers to find ICMPv6."""
    layer = ipv6_layer
    next_header = int(layer.nh)
    while next_header in _IPV6_EXTENSION_HEADERS:
        layer = layer.payload
        header = getattr(layer, "nh", None)
        if header is None:
            return False
        next_header = int(header)
    return next_header == _ICMPV6_PROTOCOL_NUMBER


def packet_to_metadata(packet: Any) -> PacketMetadata | None:
    if IP in packet:
        network_layer = packet[IP]
        source = str(network_layer.src)
        destination = str(network_layer.dst)
        fallback_protocol = str(network_layer.proto)
    elif IPv6 in packet:
        network_layer = packet[IPv6]
        source = str(network_layer.src)
        destination = str(network_layer.dst)
        fallback_protocol = str(network_layer.nh)
    else:
        return None

    protocol = fallback_protocol
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None

    if TCP in packet:
        protocol = "tcp"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "udp"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif ICMP in packet or (IPv6 in packet and _ipv6_carries_icmpv6(packet[IPv6])):
        protocol = "icmp"

    interface = getattr(packet, "sniffed_on", None)
    return PacketMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        interface=str(interface) if interface else None,
        source=source,
        destination=destination,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_length=len(packet),
        tcp_flags=tcp_flags,
    )

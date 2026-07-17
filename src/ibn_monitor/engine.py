from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from threading import RLock
from typing import Any

from scapy.config import conf

from .models import PacketMetadata, Rule

# Route discovery is unnecessary for passive capture and can fail in restricted containers.
conf.route_autoload = False
conf.route6_autoload = False

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402


class PolicyEngine:
    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self._rules = rules
        self._lock = RLock()

    def replace_rules(self, rules: tuple[Rule, ...]) -> None:
        with self._lock:
            self._rules = rules

    def snapshot(self) -> tuple[Rule, ...]:
        with self._lock:
            return self._rules

    def evaluate(self, packet: PacketMetadata) -> list[Rule]:
        source = ip_address(packet.source)
        destination = ip_address(packet.destination)
        matches: list[Rule] = []

        for rule in self.snapshot():
            if not rule.enabled:
                continue
            if rule.protocol != "any" and rule.protocol != packet.protocol:
                continue
            if rule.source_cidrs and not any(
                source.version == network.version and source in network
                for network in rule.source_cidrs
            ):
                continue
            if rule.destination_cidrs and not any(
                destination.version == network.version and destination in network
                for network in rule.destination_cidrs
            ):
                continue
            if rule.destination_ports and packet.destination_port not in rule.destination_ports:
                continue
            matches.append(rule)

        return matches


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
    elif ICMP in packet or (IPv6 in packet and int(packet[IPv6].nh) == 58):
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

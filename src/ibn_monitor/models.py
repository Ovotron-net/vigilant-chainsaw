from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import Literal

Network = IPv4Network | IPv6Network
Protocol = Literal["any", "tcp", "udp", "icmp"]
Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["alert", "drop"]


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    timestamp: str
    interface: str | None
    source: str
    destination: str
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    packet_length: int = 0
    tcp_flags: str | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    description: str
    enabled: bool
    source_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]
    protocol: Protocol
    destination_ports: frozenset[int]
    severity: Severity
    action: Action

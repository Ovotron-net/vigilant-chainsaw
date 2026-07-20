from __future__ import annotations

from dataclasses import asdict, dataclass
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


@dataclass(frozen=True, slots=True)
class Event:
    schema_version: int
    event_id: str
    event_type: str
    observed_at: str
    rule_id: str
    rule_description: str
    rule_severity: Severity
    rule_action: Action
    network: PacketMetadata

    def to_dict(self) -> dict[str, object]:
        """Wire format for JSONL / webhook /api/state — same keys as today."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "observed_at": self.observed_at,
            "rule": {
                "id": self.rule_id,
                "description": self.rule_description,
                "severity": self.rule_severity,
                "action": self.rule_action,
            },
            "network": asdict(self.network),
        }

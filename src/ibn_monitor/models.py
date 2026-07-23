from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import IntFlag
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

Network = IPv4Network | IPv6Network
Protocol = Literal["any", "tcp", "udp", "icmp"]
Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["alert", "drop"]

Address = IPv4Address | IPv6Address
PolicyProtocol = Literal["any", "tcp", "udp", "icmp"]
EnforcementDisposition = Literal["none", "nftables_drop_candidate"]
ObservedDirection = Literal["inbound", "outbound", "unknown"]
DecodeOutcome = Literal["complete", "partial", "undecodable"]
DiagnosticSeverity = Literal["error", "warning"]
EpisodePhase = Literal["start", "progress", "close"]
EpisodeCloseReason = Literal[
    "idle",
    "capacity_evicted",
    "policy_reload",
    "source_exhausted",
    "shutdown",
]


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


class FieldPresence(IntFlag):
    IP_VERSION = 1 << 0
    SOURCE = 1 << 1
    DESTINATION = 1 << 2
    PROTOCOL = 1 << 3
    SOURCE_PORT = 1 << 4
    DESTINATION_PORT = 1 << 5
    TCP_FLAGS = 1 << 6
    ICMP = 1 << 7

    @classmethod
    def complete_tcp(cls) -> FieldPresence:
        return (
            cls.IP_VERSION
            | cls.SOURCE
            | cls.DESTINATION
            | cls.PROTOCOL
            | cls.SOURCE_PORT
            | cls.DESTINATION_PORT
            | cls.TCP_FLAGS
        )


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: DiagnosticSeverity
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    source_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]
    protocol: PolicyProtocol
    destination_ports: frozenset[int] | None


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    description: str
    enabled: bool
    match: PolicyMatch
    severity: Severity
    enforcement: EnforcementDisposition


@dataclass(frozen=True, slots=True)
class Observation:
    captured_at: datetime
    monotonic_at: float | None
    sensor_id: str
    source_generation: str
    capture_point: str
    interface: str | None
    direction: ObservedDirection
    wire_length: int
    ip_version: int | None = None
    source: Address | None = None
    destination: Address | None = None
    protocol: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    fields: FieldPresence = FieldPresence(0)
    outcome: DecodeOutcome = "undecodable"
    decode_reason: str | None = None
    late: bool = False


@dataclass(frozen=True, slots=True)
class EpisodeKey:
    policy_revision: str
    rule_id: str
    ip_version: int | None
    source: Address | None
    destination: Address | None
    protocol: str | None
    source_port: int | None
    destination_port: int | None
    icmp_type: int | None
    icmp_code: int | None
    fields: int
    decode_reason: str | None


@dataclass(frozen=True, slots=True)
class EpisodeTransition:
    episode_id: str
    phase: EpisodePhase
    key: EpisodeKey
    rule: PolicyRule
    first_observed_at: datetime
    last_observed_at: datetime
    lifecycle_time: float
    observation_count: int
    observed_bytes: int
    late_observation_count: int
    per_capture_point: tuple[tuple[str, int, int], ...]
    truncated: bool = False
    close_reason: EpisodeCloseReason | None = None


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    schema_version: int
    event_id: str
    event_type: str
    sensor_id: str
    boot_id: str
    sequence: int
    emitted_at: datetime
    policy_revision: str | None
    payload: EpisodeTransition

    def to_dict(self) -> dict[str, object]:
        transition = self.payload
        key = transition.key
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "sensor_id": self.sensor_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "emitted_at": self.emitted_at.isoformat(),
            "policy_revision": self.policy_revision,
            "payload": {
                "episode_id": transition.episode_id,
                "phase": transition.phase,
                "rule": {
                    "id": transition.rule.id,
                    "description": transition.rule.description,
                    "severity": transition.rule.severity,
                    "enforcement": transition.rule.enforcement,
                },
                "flow": {
                    "ip_version": key.ip_version,
                    "source": str(key.source) if key.source else None,
                    "destination": str(key.destination) if key.destination else None,
                    "protocol": key.protocol,
                    "source_port": key.source_port,
                    "destination_port": key.destination_port,
                    "icmp_type": key.icmp_type,
                    "icmp_code": key.icmp_code,
                    "fields": key.fields,
                    "decode_reason": key.decode_reason,
                },
                "first_observed_at": transition.first_observed_at.isoformat(),
                "last_observed_at": transition.last_observed_at.isoformat(),
                "duration_seconds": max(
                    0.0,
                    (transition.last_observed_at - transition.first_observed_at).total_seconds(),
                ),
                "observation_count": transition.observation_count,
                "observed_bytes": transition.observed_bytes,
                "late_observation_count": transition.late_observation_count,
                "per_capture_point": {
                    name: {
                        "observations": observations,
                        "observed_bytes": observed_bytes,
                    }
                    for name, observations, observed_bytes in transition.per_capture_point
                },
                "truncated": transition.truncated,
                "close_reason": transition.close_reason,
            },
        }

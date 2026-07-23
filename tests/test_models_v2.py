from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network

import pytest

from ibn_monitor.models import (
    DecodeOutcome,
    Diagnostic,
    FieldPresence,
    Observation,
    PolicyMatch,
    PolicyRule,
)


def test_v2_policy_and_observation_are_frozen():
    rule = PolicyRule(
        id="DEV-DB",
        description="development must not reach production database",
        enabled=True,
        match=PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.10.8/32"),),
            protocol="tcp",
            destination_ports=frozenset({5432}),
        ),
        severity="critical",
        enforcement="nftables_drop_candidate",
    )
    observation = Observation(
        captured_at=datetime(2026, 7, 23, tzinfo=UTC),
        monotonic_at=None,
        sensor_id="sensor-1",
        source_generation="replay-0",
        capture_point="pcap",
        interface=None,
        direction="unknown",
        wire_length=60,
        ip_version=4,
        source=ip_address("10.20.5.14"),
        destination=ip_address("10.50.10.8"),
        protocol="tcp",
        source_port=40000,
        destination_port=5432,
        tcp_flags=0x02,
        fields=FieldPresence.complete_tcp(),
        outcome="complete",
    )

    with pytest.raises(FrozenInstanceError):
        rule.enabled = False
    with pytest.raises(FrozenInstanceError):
        observation.destination_port = 443


def test_field_presence_and_diagnostic_values_are_stable():
    assert int(FieldPresence.complete_tcp()) == 127
    assert DecodeOutcome.__args__ == ("complete", "partial", "undecodable")
    diagnostic = Diagnostic("warning", "rule.overlap", "/rules/1", "overlaps R1")
    assert diagnostic.to_dict() == {
        "severity": "warning",
        "code": "rule.overlap",
        "path": "/rules/1",
        "message": "overlaps R1",
    }

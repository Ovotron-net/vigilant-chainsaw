from ipaddress import ip_network

from ibn_monitor.engine import PolicyEngine
from ibn_monitor.models import PacketMetadata, Rule


def rule(**overrides):
    values = {
        "id": "DEV-DB",
        "description": "block dev database access",
        "enabled": True,
        "source_cidrs": (ip_network("10.20.0.0/16"),),
        "destination_cidrs": (ip_network("10.50.10.8/32"),),
        "protocol": "tcp",
        "destination_ports": frozenset({5432}),
        "severity": "critical",
        "action": "drop",
    }
    values.update(overrides)
    return Rule(**values)


def test_policy_matches_prohibited_flow():
    packet = PacketMetadata(
        timestamp="now",
        interface="eth0",
        source="10.20.5.14",
        destination="10.50.10.8",
        protocol="tcp",
        destination_port=5432,
    )
    assert PolicyEngine((rule(),)).evaluate(packet)[0].id == "DEV-DB"


def test_policy_ignores_allowed_port():
    packet = PacketMetadata(
        timestamp="now",
        interface="eth0",
        source="10.20.5.14",
        destination="10.50.10.8",
        protocol="tcp",
        destination_port=443,
    )
    assert PolicyEngine((rule(),)).evaluate(packet) == []

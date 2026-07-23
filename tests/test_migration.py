import json

from ibn_monitor.config import load_v2_config
from ibn_monitor.migration import MigrationRequest, migrate_v1_policy


def request():
    return MigrationRequest(
        sensor_id="edge-gw-01",
        topology="gateway",
        capture_point_name="wan",
        interface="eth0",
    )


def test_migrates_explicit_v1_rule_without_changing_input(tmp_path):
    raw = {
        "version": 1,
        "rules": [
            {
                "id": "R1",
                "description": "test",
                "enabled": True,
                "source_cidrs": ["10.0.0.0/8"],
                "destination_cidrs": ["192.0.2.1/32"],
                "protocol": "tcp",
                "destination_ports": [443],
                "severity": "high",
                "action": "drop",
            }
        ],
    }
    result = migrate_v1_policy(raw, request())
    assert result.valid
    assert raw["version"] == 1
    assert result.payload["version"] == 2
    assert result.payload["rules"][0]["enforcement"] == "nftables_drop_candidate"
    assert result.payload["sensor"]["capture_points"][0]["direction"] == "inbound"

    path = tmp_path / "migrated.json"
    path.write_text(json.dumps(result.payload), encoding="utf-8")
    assert load_v2_config(path).rules[0].id == "R1"


def test_refuses_ambiguous_missing_cidrs_and_ports():
    raw = {"version": 1, "rules": [{"id": "R1", "protocol": "tcp"}]}
    result = migrate_v1_policy(raw, request())
    assert result.payload is None
    assert [item.code for item in result.diagnostics] == [
        "migration.ambiguous_source_cidrs",
        "migration.ambiguous_destination_cidrs",
        "migration.ambiguous_destination_ports",
    ]


def test_mirror_migration_forces_promiscuous_default():
    req = MigrationRequest("mirror-1", "mirror", "span", "eth1")
    raw = {
        "version": 1,
        "rules": [
            {
                "id": "R1",
                "source_cidrs": ["0.0.0.0/0"],
                "destination_cidrs": ["0.0.0.0/0"],
                "protocol": "icmp",
            }
        ],
    }
    point = migrate_v1_policy(raw, req).payload["sensor"]["capture_points"][0]
    assert point["promiscuous"] is True


def test_rejects_non_default_bpf_filter():
    raw = {
        "version": 1,
        "sensor": {"bpf_filter": "tcp port 443"},
        "rules": [
            {
                "id": "R1",
                "source_cidrs": ["0.0.0.0/0"],
                "destination_cidrs": ["0.0.0.0/0"],
                "protocol": "icmp",
            }
        ],
    }
    result = migrate_v1_policy(raw, request())
    assert result.payload is None
    assert [item.code for item in result.diagnostics] == [
        "migration.unsupported_bpf_filter"
    ]

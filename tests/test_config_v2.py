import json

import jsonschema
import pytest

from ibn_monitor.config import (
    ConfigError,
    _load_v2_schema,
    detect_config_version,
    load_v2_config,
    validate_v2_config,
)


def write_json(tmp_path, payload):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def valid_v2():
    return {
        "version": 2,
        "sensor": {
            "id": "edge-gw-01",
            "topology": "gateway",
            "capture_points": [
                {
                    "name": "wan",
                    "interface": "eth0",
                    "direction": "inbound",
                    "promiscuous": False,
                }
            ],
        },
        "rules": [
            {
                "id": "DEV-DB",
                "description": "development must not reach production database",
                "enabled": True,
                "match": {
                    "source_cidrs": ["10.20.0.0/16"],
                    "destination_cidrs": ["10.50.10.8/32"],
                    "protocol": "tcp",
                    "destination_ports": [5432],
                },
                "severity": "critical",
                "enforcement": "nftables_drop_candidate",
            }
        ],
    }


def test_schema_is_valid_draft202012():
    jsonschema.Draft202012Validator.check_schema(_load_v2_schema())


def test_detects_and_loads_v2_with_defaults(tmp_path):
    path = write_json(tmp_path, valid_v2())
    assert detect_config_version(path) == 2
    config = load_v2_config(path)
    assert config.sensor.id == "edge-gw-01"
    assert config.processing.observation_queue_capacity == 10_000
    assert config.episodes.idle_seconds == 30
    assert len(config.policy_revision) == 64
    assert len(config.config_revision) == 64


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p["sensor"].pop("id"), "sensor/id"),
        (lambda p: p["rules"][0]["match"].update(source_cidrs=[]), "source_cidrs"),
        (lambda p: p["rules"][0]["match"].pop("protocol"), "protocol"),
        (
            lambda p: p["rules"][0]["match"].update(protocol="icmp", destination_ports=[8]),
            "destination_ports",
        ),
    ],
)
def test_rejects_implicit_or_invalid_v2_selectors(tmp_path, mutate, message):
    payload = valid_v2()
    mutate(payload)
    with pytest.raises(ConfigError, match=message):
        load_v2_config(write_json(tmp_path, payload))


def test_mirror_requires_promiscuous_capture(tmp_path):
    payload = valid_v2()
    payload["sensor"]["topology"] = "mirror"
    with pytest.raises(ConfigError, match="sensor.mirror_promiscuous"):
        load_v2_config(write_json(tmp_path, payload))


def test_revisions_ignore_json_order_but_include_description(tmp_path):
    first = valid_v2()
    second = json.loads(json.dumps(first, sort_keys=True))
    assert load_v2_config(write_json(tmp_path, first)).policy_revision == load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision

    second["rules"][0]["description"] = "changed description"
    assert load_v2_config(write_json(tmp_path, first)).policy_revision != load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision


def test_revision_normalizes_and_deduplicates_equivalent_cidrs(tmp_path):
    first = valid_v2()
    second = valid_v2()
    second["rules"][0]["match"]["source_cidrs"] = [
        "10.20.5.14/16",
        "10.20.0.0/16",
    ]
    assert load_v2_config(write_json(tmp_path, first)).policy_revision == load_v2_config(
        write_json(tmp_path, second)
    ).policy_revision


def test_strict_mode_raises_on_overlap_warning(tmp_path):
    payload = valid_v2()
    payload["rules"].append(
        {
            "id": "DEV-DB-2",
            "description": "overlapping rule",
            "enabled": True,
            "match": {
                "source_cidrs": ["10.20.0.0/16"],
                "destination_cidrs": ["10.50.10.8/32"],
                "protocol": "tcp",
                "destination_ports": [5432],
            },
            "severity": "high",
            "enforcement": "none",
        }
    )
    path = write_json(tmp_path, payload)
    result = validate_v2_config(path)
    assert result.valid
    assert any(item.code == "rule.overlap" for item in result.diagnostics)
    load_v2_config(path)
    with pytest.raises(ConfigError, match="rule.overlap"):
        load_v2_config(path, strict=True)

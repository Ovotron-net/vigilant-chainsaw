import json

import pytest

from ibn_monitor.config import ConfigError, load_config


def test_loads_valid_configuration(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "test",
                        "source_cidrs": ["10.0.0.0/8"],
                        "destination_cidrs": ["192.168.1.10"],
                        "protocol": "tcp",
                        "destination_ports": [443],
                        "severity": "high",
                        "action": "alert",
                    }
                ],
            }
        )
    )
    config = load_config(path)
    assert config.rules[0].id == "test"
    assert str(config.rules[0].destination_cidrs[0]) == "192.168.1.10/32"


def test_rejects_ports_for_icmp(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "bad",
                        "protocol": "icmp",
                        "destination_ports": [80],
                    }
                ]
            }
        )
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_rejects_unknown_top_level_key(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rulez": [],
                "rules": [{"id": "test"}],
            }
        )
    )
    with pytest.raises(ConfigError, match="rulez"):
        load_config(path)


def test_rejects_missing_version(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": [{"id": "test"}]}))
    with pytest.raises(ConfigError, match="version"):
        load_config(path)


def test_rejects_duplicate_destination_ports(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "test",
                        "protocol": "tcp",
                        "destination_ports": [443, 443],
                    }
                ],
            }
        )
    )
    with pytest.raises(ConfigError, match="destination_ports"):
        load_config(path)


def test_rejects_duplicate_rule_ids(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [{"id": "x"}, {"id": "x"}],
            }
        )
    )
    with pytest.raises(ConfigError, match="unique"):
        load_config(path)


def test_rejects_invalid_cidr(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [{"id": "x", "source_cidrs": ["not-a-cidr"]}],
            }
        )
    )
    with pytest.raises(ConfigError, match="CIDR"):
        load_config(path)

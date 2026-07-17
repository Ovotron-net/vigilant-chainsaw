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

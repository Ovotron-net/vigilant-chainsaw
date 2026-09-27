import json
import logging

import pytest

from ibn_monitor.cli import main

V1_POLICY = {
    "version": 1,
    "rules": [
        {
            "id": "R1",
            "description": "test",
            "source_cidrs": ["10.20.0.0/16"],
            "destination_cidrs": ["10.50.10.8/32"],
            "protocol": "tcp",
            "destination_ports": [5432],
            "severity": "critical",
            "action": "drop",
        }
    ],
}


def write_v1_policy(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(V1_POLICY), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    "extra",
    [
        ["validate"],
        ["render-nftables"],
        [
            "check",
            "--source",
            "10.20.5.14",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
        ],
    ],
    ids=["validate", "render-nftables", "check"],
)
def test_v1_policy_is_rejected_with_migration_hint(tmp_path, caplog, extra):
    command, *rest = extra
    with caplog.at_level(logging.ERROR):
        code = main([command, "--config", write_v1_policy(tmp_path), *rest])
    assert code == 2
    assert "migrate-policy" in caplog.text


def test_check_rejects_invalid_ip_without_traceback():
    code = main(
        [
            "check",
            "--source",
            "not-an-ip",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
        ]
    )
    assert code == 2

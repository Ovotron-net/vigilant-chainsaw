import json

from ibn_monitor.cli import main

POLICY = {
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


def write_policy(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY), encoding="utf-8")
    return str(path)


def test_validate_reports_rule_counts(tmp_path, capsys):
    assert main(["validate", "--config", write_policy(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"valid": True, "version": 1, "enabled_rules": 1, "drop_rules": 1}


def test_check_exit_code_2_on_match(tmp_path, capsys):
    code = main(
        [
            "check",
            "--config",
            write_policy(tmp_path),
            "--source",
            "10.20.5.14",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
            "--destination-port",
            "5432",
        ]
    )
    assert code == 2
    assert json.loads(capsys.readouterr().out)["matched"] is True


def test_check_rejects_invalid_ip_without_traceback(tmp_path):
    code = main(
        [
            "check",
            "--config",
            write_policy(tmp_path),
            "--source",
            "not-an-ip",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
        ]
    )
    assert code == 2

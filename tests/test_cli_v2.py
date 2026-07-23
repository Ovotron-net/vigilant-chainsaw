import json

import pytest
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from pcap_bytes import classic_pcap

from ibn_monitor.cli import main


@pytest.fixture
def v2_policy_path():
    return "config/policy.v2.example.json"


@pytest.fixture
def pcap_path(tmp_path):
    frame = ethernet_frame(ipv4_packet(tcp_header(), protocol=6))
    path = tmp_path / "sample.pcap"
    path.write_bytes(classic_pcap([(1_700_000_000, 0, frame, len(frame))]))
    return path


def test_validate_v2_reports_revision(v2_policy_path, capsys):
    assert main(["validate", "--config", str(v2_policy_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["version"] == 2
    assert len(payload["policy_revision"]) == 64


def test_check_v2_returns_one_for_violation(v2_policy_path, capsys):
    code = main(
        [
            "check",
            "--config",
            str(v2_policy_path),
            "--source",
            "10.20.5.14",
            "--destination",
            "10.50.10.8",
            "--protocol",
            "tcp",
            "--source-port",
            "40000",
            "--destination-port",
            "5432",
            "--format",
            "json",
        ]
    )
    assert code == 1
    assert json.loads(capsys.readouterr().out)["rules"][0]["id"] == "DEV-DB"


def test_replay_requires_v2_and_separate_output_paths(
    v2_policy_path, pcap_path, tmp_path, capsys
):
    events = tmp_path / "events.jsonl"
    summary = tmp_path / "summary.json"
    assert (
        main(
            [
                "replay",
                "--config",
                str(v2_policy_path),
                "--pcap",
                str(pcap_path),
                "--output",
                str(events),
                "--summary-output",
                str(summary),
                "--boot-id",
                "test-replay",
            ]
        )
        == 0
    )
    assert events.read_text(encoding="utf-8")
    assert json.loads(summary.read_text(encoding="utf-8"))["observations"] >= 1


def test_migrate_policy_refuses_overwrite_and_preserves_input(tmp_path):
    source = tmp_path / "v1.json"
    source.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "R1",
                        "description": "test",
                        "source_cidrs": ["10.0.0.0/8"],
                        "destination_cidrs": ["192.0.2.1/32"],
                        "protocol": "tcp",
                        "destination_ports": [443],
                        "severity": "high",
                        "action": "drop",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    original = source.read_text(encoding="utf-8")
    output = tmp_path / "v2.json"
    assert (
        main(
            [
                "migrate-policy",
                "--config",
                str(source),
                "--output",
                str(output),
                "--sensor-id",
                "edge-gw-01",
                "--topology",
                "gateway",
                "--capture-point",
                "wan=eth0",
            ]
        )
        == 0
    )
    assert source.read_text(encoding="utf-8") == original
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == 2
    assert (
        main(
            [
                "migrate-policy",
                "--config",
                str(source),
                "--output",
                str(output),
                "--sensor-id",
                "edge-gw-01",
                "--topology",
                "gateway",
                "--capture-point",
                "wan=eth0",
            ]
        )
        == 2
    )

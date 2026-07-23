import json

from factories import policy_rule, v2_config
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from pcap_bytes import classic_pcap

from ibn_monitor.replay import replay_pcap


def record(seconds, destination_port=5432):
    frame = ethernet_frame(
        ipv4_packet(tcp_header(destination_port=destination_port), protocol=6)
    )
    return (seconds, 0, frame, len(frame))


def test_replay_emits_start_and_source_exhausted_close(tmp_path):
    config = v2_config()
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([record(10), record(11)]))
    output = tmp_path / "events.jsonl"
    with output.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, pcap, stream, boot_id="replay-1")
    events = [json.loads(line) for line in output.read_text().splitlines()]
    assert [event["payload"]["phase"] for event in events] == ["start", "close"]
    assert events[-1]["payload"]["close_reason"] == "source_exhausted"
    assert events[-1]["payload"]["observation_count"] == 2
    assert summary.observations == 2
    assert summary.matched_observations == 2
    assert summary.episodes_started == 1
    assert summary.episodes_closed == 1


def test_replay_marks_arrival_older_than_finalized_watermark(tmp_path):
    config = v2_config()
    pcap = tmp_path / "late.pcap"
    pcap.write_bytes(classic_pcap([record(10), record(20), record(5)]))
    output = tmp_path / "events.jsonl"
    with output.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, pcap, stream, boot_id="replay-2")
    assert summary.late_observations == 1


def test_replay_is_deterministic_for_same_boot_id(tmp_path):
    config = v2_config()
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([record(10), record(11)]))
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    with first.open("w", encoding="utf-8") as stream:
        replay_pcap(config, pcap, stream, boot_id="same")
    with second.open("w", encoding="utf-8") as stream:
        replay_pcap(config, pcap, stream, boot_id="same")
    assert first.read_bytes() == second.read_bytes()


def test_replay_boot_id_only_changes_identity_fields(tmp_path):
    config = v2_config()
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([record(10)]))
    left_path = tmp_path / "left.jsonl"
    right_path = tmp_path / "right.jsonl"
    with left_path.open("w", encoding="utf-8") as stream:
        replay_pcap(config, pcap, stream, boot_id="boot-a")
    with right_path.open("w", encoding="utf-8") as stream:
        replay_pcap(config, pcap, stream, boot_id="boot-b")
    left = [json.loads(line) for line in left_path.read_text().splitlines()]
    right = [json.loads(line) for line in right_path.read_text().splitlines()]
    assert len(left) == len(right)
    for left_event, right_event in zip(left, right, strict=True):
        assert left_event["sequence"] == right_event["sequence"]
        assert left_event["payload"]["phase"] == right_event["payload"]["phase"]
        assert left_event["payload"]["flow"] == right_event["payload"]["flow"]
        assert left_event["payload"]["rule"] == right_event["payload"]["rule"]
        assert left_event["boot_id"] != right_event["boot_id"]
        assert left_event["event_id"] != right_event["event_id"]


def test_replay_reports_all_matching_rules(tmp_path):
    config = v2_config(
        rules=(
            policy_rule(id="A"),
            policy_rule(id="B", enforcement="none"),
        )
    )
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([record(10)]))
    output = tmp_path / "events.jsonl"
    with output.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, pcap, stream, boot_id="multi")
    events = [json.loads(line) for line in output.read_text().splitlines()]
    starts = [event for event in events if event["payload"]["phase"] == "start"]
    closes = [event for event in events if event["payload"]["phase"] == "close"]
    assert [event["payload"]["rule"]["id"] for event in starts] == ["A", "B"]
    assert [event["payload"]["rule"]["id"] for event in closes] == ["A", "B"]
    assert summary.matched_observations == 1
    assert summary.rule_matches == 2

"""Episode processor interface: evaluation, sequencing, counts, and live/replay parity."""

import json
import time
from datetime import UTC, datetime

from factories import observation, policy_rule, v2_config
from packet_bytes import ethernet_frame, ipv4_packet, tcp_header
from pcap_bytes import classic_pcap

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor
from ibn_monitor.processing import EpisodeProcessor, ProcessingCounts
from ibn_monitor.replay import replay_pcap

NOW = datetime(2026, 7, 23, tzinfo=UTC)


def test_matches_open_episodes_in_sorted_rule_id_order():
    rules = (policy_rule(id="B"), policy_rule(id="A", enforcement="none"))
    processor = EpisodeProcessor(v2_config(rules=rules), boot_id="boot")

    emitted = processor.observe(observation(), lifecycle_time=0.0, emitted_at=NOW)

    assert [e.payload.rule.id for e in emitted] == ["A", "B"]
    assert [e.sequence for e in emitted] == [1, 2]
    assert [e.payload.episode_id for e in emitted] == ["boot:episode:1", "boot:episode:2"]


def test_counts_cover_outcomes_matches_and_phases():
    processor = EpisodeProcessor(v2_config(), boot_id="boot")
    processor.observe(observation(), lifecycle_time=0.0, emitted_at=NOW)
    processor.observe(observation(destination_port=80), lifecycle_time=1.0, emitted_at=NOW)
    processor.observe(
        observation(outcome="undecodable", late=True, destination_port=80),
        lifecycle_time=2.0,
        emitted_at=NOW,
    )
    processor.close_all("shutdown", lifecycle_time=3.0, emitted_at=NOW)

    assert processor.counts() == ProcessingCounts(
        observations=3,
        complete=2,
        undecodable=1,
        late=1,
        matched_observations=1,
        rule_matches=1,
        episodes_started=1,
        episodes_closed=1,
    )


def test_tick_closes_idle_episodes():
    config = v2_config()
    processor = EpisodeProcessor(config, boot_id="boot")
    processor.observe(observation(), lifecycle_time=0.0, emitted_at=NOW)

    emitted = processor.tick(lifecycle_time=config.episodes.idle_seconds, emitted_at=NOW)

    assert [(e.payload.phase, e.payload.close_reason) for e in emitted] == [("close", "idle")]
    assert processor.active_episodes() == ()


def test_system_events_share_the_sequence_and_drop_none_fields():
    processor = EpisodeProcessor(v2_config(), boot_id="boot")
    processor.observe(observation(), lifecycle_time=0.0, emitted_at=NOW)

    (envelope,) = processor.system(
        "source_failed", {"capture_point": "wan", "detail": None}, emitted_at=NOW
    )

    assert envelope.sequence == 2
    assert envelope.payload.fields == {"capture_point": "wan"}


def _episode_shape(envelopes: list[dict]) -> list[tuple]:
    """Phase/rule/flow/count per episode transition, ignoring clocks and ids."""
    shape = []
    for item in envelopes:
        if item["event_type"] != "violation_episode":
            continue
        payload = item["payload"]
        flow = payload["flow"]
        shape.append(
            (
                payload["phase"],
                payload["rule"]["id"],
                flow["source"],
                flow["destination"],
                flow["protocol"],
                flow["destination_port"],
                payload["observation_count"],
            )
        )
    return shape


def test_live_and_replay_produce_the_same_episodes(tmp_path):
    config = v2_config()
    frames = [
        ethernet_frame(ipv4_packet(tcp_header(destination_port=port), protocol=6))
        for port in (5432, 5432, 80)
    ]
    pcap = tmp_path / "flows.pcap"
    pcap.write_bytes(classic_pcap([(10 + i, 0, f, len(f)) for i, f in enumerate(frames)]))
    replay_out = tmp_path / "replay.jsonl"
    with replay_out.open("w", encoding="utf-8") as stream:
        replay_pcap(config, pcap, stream, boot_id="parity")

    replayed = [json.loads(line) for line in replay_out.read_text(encoding="utf-8").splitlines()]

    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_path="unused.json",
        sources=(source,),
        evidence=evidence,
        boot_id="parity",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        base = time.monotonic()
        for index, port in enumerate((5432, 5432, 80)):
            source.push(
                observation(capture_point="wan", destination_port=port, monotonic_at=base + index)
            )
        deadline = time.time() + 2
        while time.time() < deadline and not evidence.events:
            time.sleep(0.02)
    finally:
        monitor.stop()

    live = _episode_shape([e.to_dict() for e in evidence.events])
    assert [(phase, rule, count) for phase, rule, *_, count in live] == [
        ("start", "DEV-DB", 1),
        ("close", "DEV-DB", 2),
    ]
    assert live == _episode_shape(replayed)

from datetime import UTC, datetime

import pytest
from factories import observation, policy_rule

from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.events import EvidenceSequencer, _serialize_evidence_dict


def test_episode_envelope_has_stable_identity_and_wire_shape():
    tracker = EpisodeTracker(
        EpisodeSettings(10, 30, 60),
        id_factory=lambda: "episode-1",
    )
    transition = tracker.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )[0]
    sequencer = EvidenceSequencer("sensor-1", "boot-1")
    event = sequencer.wrap_episode(
        transition,
        emitted_at=datetime(2026, 7, 23, tzinfo=UTC),
    )
    assert event.to_dict() == {
        "schema_version": 2,
        "event_id": "boot-1:1",
        "event_type": "violation_episode",
        "sensor_id": "sensor-1",
        "boot_id": "boot-1",
        "sequence": 1,
        "emitted_at": "2026-07-23T00:00:00+00:00",
        "policy_revision": "a" * 64,
        "payload": {
            "episode_id": "episode-1",
            "phase": "start",
            "rule": {
                "id": "DEV-DB",
                "description": "development must not reach production database",
                "severity": "critical",
                "enforcement": "nftables_drop_candidate",
            },
            "flow": {
                "ip_version": 4,
                "source": "10.20.5.14",
                "destination": "10.50.10.8",
                "protocol": "tcp",
                "source_port": 40000,
                "destination_port": 5432,
                "icmp_type": None,
                "icmp_code": None,
                "fields": 127,
                "decode_reason": None,
            },
            "first_observed_at": "2026-07-23T00:00:00+00:00",
            "last_observed_at": "2026-07-23T00:00:00+00:00",
            "duration_seconds": 0.0,
            "observation_count": 1,
            "observed_bytes": 60,
            "late_observation_count": 0,
            "per_capture_point": {
                "pcap": {"observations": 1, "observed_bytes": 60}
            },
            "truncated": False,
            "close_reason": None,
        },
    }


def test_evidence_line_byte_bound():
    # Binary search largest ASCII string value whose encoded line + newline fits.
    base = {"k": ""}
    low = 0
    high = 300_000
    while low < high:
        mid = (low + high + 1) // 2
        base["k"] = "a" * mid
        try:
            _serialize_evidence_dict(base)
        except ValueError:
            high = mid - 1
        else:
            low = mid
    base["k"] = "a" * low
    _serialize_evidence_dict(base)
    base["k"] = "a" * (low + 1)
    with pytest.raises(ValueError, match="evidence event exceeds 262144 bytes"):
        _serialize_evidence_dict(base)

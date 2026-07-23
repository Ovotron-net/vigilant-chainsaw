from datetime import UTC, datetime
from pathlib import Path

from factories import observation, policy_rule

from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.events import EvidenceSequencer
from ibn_monitor.journal import JournalConfig, JournalWriter


def _start_envelope(boot: str = "b1"):
    tracker = EpisodeTracker(EpisodeSettings(10, 30, 60), id_factory=lambda: "ep-1")
    transition = tracker.observe(
        policy_rule(),
        observation(),
        policy_revision="a" * 64,
        lifecycle_time=0,
    )[0]
    return EvidenceSequencer("sensor-1", boot).wrap_episode(
        transition, emitted_at=datetime(2026, 7, 24, tzinfo=UTC)
    )


def test_journal_writes_and_fsyncs(tmp_path):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(
        JournalConfig(file=str(path), max_bytes=1_000_000, fsync_interval_seconds=0.01)
    )
    writer.commit(_start_envelope())
    writer.flush()
    writer.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert '"schema_version":2' in lines[0]


def test_journal_rotates_when_max_bytes_exceeded(tmp_path):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(
        JournalConfig(
            file=str(path), max_bytes=200, backup_count=2, fsync_interval_seconds=60
        )
    )
    for index in range(20):
        writer.commit(_start_envelope(boot=f"b{index}"))
    writer.close()
    assert path.exists() or Path(f"{path}.1").exists()


def test_journal_emergency_buffer_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(JournalConfig(file=str(path), emergency_max_events=5))
    writer.commit(_start_envelope("ok"))

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(writer, "_write_line", boom)
    writer._healthy = True
    writer.commit(_start_envelope("fail"))
    assert writer.healthy is False
    assert len(writer._emergency) >= 1

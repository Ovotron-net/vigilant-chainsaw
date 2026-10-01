from datetime import UTC, datetime
from pathlib import Path

from factories import observation, policy_rule

from ibn_monitor.config import JournalV2Config
from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.evidence import EvidenceSequencer
from ibn_monitor.journal import JournalWriter


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
        JournalV2Config(file=str(path), max_bytes=1_000_000, fsync_interval_seconds=0.01)
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
        JournalV2Config(file=str(path), max_bytes=200, backup_count=2, fsync_interval_seconds=60)
    )
    for index in range(20):
        writer.commit(_start_envelope(boot=f"b{index}"))
    writer.close()
    assert path.exists() or Path(f"{path}.1").exists()


def test_journal_emergency_buffer_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(JournalV2Config(file=str(path), emergency_max_events=5))
    writer.commit(_start_envelope("ok"))

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(writer, "_write_line", boom)
    writer._healthy = True
    writer.commit(_start_envelope("fail"))
    assert writer.healthy is False
    assert len(writer._emergency) >= 1


def test_journal_periodic_maintenance_recovers_and_drains(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(JournalV2Config(file=str(path), emergency_max_events=5))
    original = writer._write_line
    failed = False

    def fail_once(line):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("temporary failure")
        original(line)

    monkeypatch.setattr(writer, "_write_line", fail_once)
    writer.commit(_start_envelope("recovered"))
    assert not writer.healthy

    writer.maintain()

    assert writer.healthy
    assert not writer._emergency
    writer.close()
    assert '"boot_id":"recovered"' in path.read_text(encoding="utf-8")


def test_failed_or_forced_flush_does_not_mark_clean(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    marker = path.with_suffix(".jsonl.clean")
    writer = JournalWriter(JournalV2Config(file=str(path)))
    writer.commit(_start_envelope())
    monkeypatch.setattr(writer, "_sync", lambda **_kwargs: (_ for _ in ()).throw(OSError()))

    writer.flush()
    writer.close()

    assert not marker.exists()

    forced = JournalWriter(JournalV2Config(file=str(path)))
    monkeypatch.undo()
    forced.commit(_start_envelope("forced"))
    forced.flush(mark_clean=False)
    forced.close()
    assert not marker.exists()


def test_rotation_fsyncs_segment_before_rename(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    writer = JournalWriter(JournalV2Config(file=str(path), max_bytes=1, fsync_interval_seconds=60))
    syncs = 0
    original = writer._sync

    def counted_sync(**kwargs):
        nonlocal syncs
        syncs += 1
        original(**kwargs)

    monkeypatch.setattr(writer, "_sync", counted_sync)
    writer.commit(_start_envelope())
    writer.close()

    assert syncs >= 2  # rotation and close


def test_periodic_maintenance_fsyncs_idle_journal(tmp_path, monkeypatch):
    writer = JournalWriter(
        JournalV2Config(
            file=str(tmp_path / "events.jsonl"),
            max_bytes=1_000_000,
            fsync_interval_seconds=60,
        )
    )
    writer.commit(_start_envelope())
    syncs = 0
    original = writer._sync

    def counted_sync(**kwargs):
        nonlocal syncs
        syncs += 1
        original(**kwargs)

    monkeypatch.setattr(writer, "_sync", counted_sync)
    writer._last_fsync = 0
    writer.maintain()
    writer.close()

    assert syncs >= 1

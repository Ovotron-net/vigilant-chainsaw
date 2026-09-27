"""Operational state machine: ready / degraded / stopping and their reasons."""

from ibn_monitor.ops_state import OperationalStateMachine


def _machine(*points: str) -> OperationalStateMachine:
    machine = OperationalStateMachine(
        sensor_id="s",
        boot_id="b",
        queue_capacity=10,
        sources=tuple((point, f"eth-{point}") for point in points),
    )
    machine.set_policy("p" * 64, "c" * 64)
    return machine


def _ready(*points: str) -> OperationalStateMachine:
    machine = _machine(*points)
    for point in points:
        machine.set_source(point, state="established", source_generation="g1")
    assert machine.snapshot().state == "ready"
    return machine


def test_starts_starting_and_becomes_ready_when_all_sources_established():
    machine = _machine("wan", "lan")
    assert machine.snapshot().state == "starting"
    machine.set_source("wan", state="established")
    assert not machine.snapshot().ready
    machine.set_source("lan", state="established")
    snap = machine.snapshot()
    assert (snap.state, snap.ready, snap.reasons) == ("ready", True, frozenset())


def test_missing_policy_is_a_reason():
    machine = _ready("wan")
    machine.set_policy(None, None)
    snap = machine.snapshot()
    assert snap.state == "degraded"
    assert "no_policy" in snap.reasons


def test_failed_source_degrades_until_it_recovers():
    machine = _ready("wan")
    machine.set_source("wan", state="failed", last_error="boom")
    snap = machine.snapshot()
    assert (snap.state, snap.reasons) == ("degraded", frozenset({"capture_point_unavailable"}))
    assert snap.sources[0].last_error == "boom"
    machine.set_source("wan", state="established")
    assert machine.snapshot().state == "ready"
    assert machine.snapshot().sources[0].last_error is None


def test_kernel_drops_count_deltas_and_clear():
    machine = _ready("wan")
    assert machine.note_kernel_drops("wan", 5) == 5
    assert machine.note_kernel_drops("wan", 5) == 0
    assert machine.note_kernel_drops("wan", 8) == 3
    snap = machine.snapshot()
    assert (snap.state, snap.kernel_drops_total) == ("degraded", 8)
    assert "kernel_drops" in snap.reasons
    machine.clear_kernel_drops()
    assert machine.snapshot().state == "ready"


def test_app_queue_drops_degrade_and_clear():
    machine = _ready("wan")
    machine.note_app_drops(0)
    assert machine.snapshot().state == "ready"
    machine.note_app_drops(4)
    snap = machine.snapshot()
    assert (snap.state, snap.app_queue_drops_total) == ("degraded", 4)
    machine.clear_app_drops()
    assert machine.snapshot().state == "ready"


def test_worker_dead_degrades():
    machine = _ready("wan")
    machine.mark_worker_dead()
    assert "worker_dead" in machine.snapshot().reasons
    assert not machine.snapshot().ready


def test_shutdown_is_stopping_and_does_not_report_capture_unavailable():
    machine = _ready("wan")
    machine.mark_shutdown()
    machine.set_source("wan", state="stopped")
    snap = machine.snapshot()
    assert snap.state == "stopping"
    assert "capture_point_unavailable" not in snap.reasons

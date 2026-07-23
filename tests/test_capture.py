from factories import observation

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.models import ControlMessage, SourceStatsSnapshot


def test_memory_source_pushes_observation_and_lifecycle():
    source = MemoryObservationSource("wan")
    observations = []
    controls = []
    source.start(observations.append, controls.append)
    source.push(observation(capture_point="wan"))
    source.emit_stats(
        SourceStatsSnapshot(
            capture_point="wan",
            source_generation="wan:test:1",
            kernel_packets=1,
            kernel_drops=0,
            app_enqueue_ok=1,
            app_enqueue_drops=0,
            decode_complete=1,
            decode_partial=0,
            decode_undecodable=0,
        )
    )
    source.stop()

    assert len(observations) == 1
    assert observations[0].destination_port == 5432
    kinds = [msg.kind for msg in controls]
    assert "source_established" in kinds
    assert "source_stats" in kinds
    assert "source_stopped" in kinds
    assert source.stopped


def test_memory_source_emit_failed():
    source = MemoryObservationSource("wan", auto_establish=False)
    controls: list[ControlMessage] = []
    source.start(lambda _: None, controls.append)
    source.emit_failed("enoent")
    assert controls[-1].kind == "source_failed"
    assert controls[-1].detail == "enoent"

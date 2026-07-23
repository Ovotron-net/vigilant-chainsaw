from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from .capture import ObservationSource
from .config import PolicyV2Config
from .evidence_stub import EvidenceWriter, FileEvidenceWriter
from .models import ControlMessage
from .notifications_v2 import build_v2_notifier
from .pipeline import PipelineConfig, PipelineWorker
from .probe import ProbeServer

logger = logging.getLogger(__name__)


class LiveMonitor:
    """V2 live composition: sources + pipeline worker + minimal probe."""

    def __init__(
        self,
        config: PolicyV2Config,
        *,
        config_path: str,
        sources: tuple[ObservationSource, ...] | None = None,
        evidence: EvidenceWriter | None = None,
        boot_id: str | None = None,
        probe_enabled: bool | None = None,
    ) -> None:
        self._config = config
        self._config_path = config_path
        self._boot_id = boot_id or str(uuid.uuid4())
        if evidence is None:
            journal = config.journal
            evidence = FileEvidenceWriter(
                Path(journal.file),
                max_bytes=journal.max_bytes,
                backup_count=journal.backup_count,
                fsync_interval_seconds=journal.fsync_interval_seconds,
                emergency_max_events=journal.emergency_max_events,
                emergency_max_bytes=journal.emergency_max_bytes,
            )
        self._evidence = evidence
        self._notifier = build_v2_notifier(config.notifications)
        if sources is None:
            from .capture_afpacket import build_af_packet_sources

            sources = build_af_packet_sources(config, boot_id=self._boot_id)
        self._sources = sources
        self._worker = PipelineWorker(
            config,
            pipeline_config=PipelineConfig(
                observation_capacity=config.processing.observation_queue_capacity,
                queue_recovery_cooldown_seconds=(
                    config.processing.queue_recovery_cooldown_seconds
                ),
                graceful_drain_seconds=config.processing.graceful_drain_seconds,
                config_path=config_path,
            ),
            evidence=self._evidence,
            boot_id=self._boot_id,
            notifier=self._notifier,
        )
        enabled = config.http.probe.enabled if probe_enabled is None else probe_enabled
        self._probe = ProbeServer(
            type(config.http.probe)(
                enabled=enabled,
                bind=config.http.probe.bind,
                port=config.http.probe.port,
                allow_non_loopback=config.http.probe.allow_non_loopback,
            ),
            self._worker.snapshot,
        )

    @property
    def boot_id(self) -> str:
        return self._boot_id

    @property
    def sources(self) -> tuple[ObservationSource, ...]:
        return self._sources

    def start(self) -> None:
        self._notifier.start()
        self._worker.start()
        for source in self._sources:
            source.start(self._worker.observation_sink, self._worker.control_sink)
        self._probe.start()
        logger.info(
            "LiveMonitor started boot_id=%s sensor_id=%s",
            self._boot_id,
            self._config.sensor.id,
        )

    def stop(self, *, force: bool = False) -> None:
        for source in self._sources:
            source.stop()
        self._worker.stop(force=force)
        self._probe.stop()
        self._notifier.stop(
            drain_seconds=self._config.notifications.shutdown_drain_seconds
        )
        close = getattr(self._evidence, "close", None)
        if callable(close):
            close()

    def request_reload(self) -> None:
        self._worker.control_sink(
            ControlMessage(kind="reload_request", monotonic_at=time.monotonic())
        )

    def request_shutdown(self, *, force: bool = False) -> None:
        self._worker.control_sink(
            ControlMessage(
                kind="force_shutdown" if force else "shutdown",
                monotonic_at=time.monotonic(),
            )
        )

    def snapshot(self):
        return self._worker.snapshot()

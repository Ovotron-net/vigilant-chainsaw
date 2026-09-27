from __future__ import annotations

import logging
import time
import uuid
from dataclasses import replace

from .capture import ObservationSource
from .config import ConfigSource, PolicyV2Config
from .evidence import EvidenceWriter
from .journal import JournalWriter
from .models import ControlMessage, OperationalSnapshot
from .notifications_v2 import build_v2_notifier
from .operations import OperationsServer
from .pipeline import PipelineConfig, PipelineWorker
from .probe import ProbeServer

logger = logging.getLogger(__name__)


class LiveMonitor:
    """V2 live composition: sources + pipeline worker + probe and operations HTTP."""

    def __init__(
        self,
        config: PolicyV2Config,
        *,
        config_source: ConfigSource | None,
        sources: tuple[ObservationSource, ...] | None = None,
        evidence: EvidenceWriter | None = None,
        boot_id: str | None = None,
        probe_enabled: bool | None = None,
        operations_enabled: bool | None = None,
    ) -> None:
        self._config = config
        self._boot_id = boot_id or str(uuid.uuid4())
        self._evidence: EvidenceWriter = evidence or JournalWriter(config.journal)
        self._notifier = build_v2_notifier(config.notifications)
        if sources is None:
            from .capture_live import build_live_sources

            sources = build_live_sources(config, boot_id=self._boot_id)
        self._sources = sources
        self._worker = PipelineWorker(
            config,
            pipeline_config=PipelineConfig(
                observation_capacity=config.processing.observation_queue_capacity,
                queue_recovery_cooldown_seconds=config.processing.queue_recovery_cooldown_seconds,
                graceful_drain_seconds=config.processing.graceful_drain_seconds,
                config_source=config_source,
            ),
            evidence=self._evidence,
            boot_id=self._boot_id,
            notifier=self._notifier,
        )
        probe = config.http.probe
        self._probe = ProbeServer(
            replace(probe, enabled=probe.enabled if probe_enabled is None else probe_enabled),
            self._worker.snapshot,
            metrics_provider=self._worker.metrics_text,
        )
        ops = config.http.operations
        ops_enabled = ops.enabled if operations_enabled is None else operations_enabled
        # When tests disable probe, default operations off too unless overridden.
        if probe_enabled is False and operations_enabled is None:
            ops_enabled = False
        self._operations = OperationsServer(
            replace(ops, enabled=ops_enabled),
            self._worker.operations_state,
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
        self._operations.start()
        logger.info(
            "LiveMonitor started boot_id=%s sensor_id=%s",
            self._boot_id,
            self._config.sensor.id,
        )

    def stop(self, *, force: bool = False) -> None:
        for source in self._sources:
            source.stop()
        # The worker's shutdown path closes episodes, flushes evidence and drains the notifier.
        self._worker.stop(force=force)
        self._operations.stop()
        self._probe.stop()
        self._evidence.close()

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

    def snapshot(self) -> OperationalSnapshot:
        return self._worker.snapshot()

    def operations_state(self) -> dict[str, object]:
        return self._worker.operations_state()

    def metrics_text(self) -> str:
        return self._worker.metrics_text()

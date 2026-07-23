from __future__ import annotations

import logging
import uuid
from pathlib import Path

from .capture import ObservationSource, PacketSource
from .config import AppConfig, PolicyV2Config
from .engine import PolicyEngine
from .events import EventLog, Metrics, build_notifier, create_event
from .evidence_stub import EvidenceWriter, FileEvidenceWriter
from .health import HealthServer
from .models import PacketMetadata, Rule
from .pipeline import PipelineConfig, PipelineWorker
from .probe import ProbeServer

logger = logging.getLogger(__name__)


class MonitorService:
    """V1 live monitor (Scapy path). Kept until Phase 5 render cut completes."""

    def __init__(self, config: AppConfig, source: PacketSource) -> None:
        self.config = config
        self.source = source
        self.engine = PolicyEngine(config.rules)
        self.metrics = Metrics()
        self.event_log = EventLog(config.logging)
        self.notifier = build_notifier(config.notifications, self.metrics)
        self.health = HealthServer(
            config.health,
            self.metrics,
            rules_provider=self.engine.snapshot,
            events_provider=self.event_log.recent,
        )

    def start(self) -> None:
        try:
            self.notifier.start()
            self.health.start()
            logging.getLogger(__name__).info(
                "Monitoring interface=%s filter=%s",
                self.config.sensor.interface or "default",
                self.config.sensor.bpf_filter,
            )
            self.source.start(
                self.on_packet, on_established=lambda: self.metrics.set_ready(True)
            )
        except Exception:
            self.stop()
            raise

    def on_packet(self, metadata: PacketMetadata | None) -> None:
        self.metrics.mark_packet(decoded=metadata is not None)
        if metadata is None:
            return

        for rule in self.engine.evaluate(metadata):
            self.metrics.mark_violation()
            event = create_event(metadata, rule)
            self.event_log.write(event)
            self.notifier.notify(event)

    def reload_rules(self, rules: tuple[Rule, ...]) -> None:
        self.engine.replace_rules(rules)
        logging.getLogger(__name__).info("Reloaded %d policy rules", len(rules))

    def stop(self) -> None:
        self.metrics.set_ready(False)
        self.source.stop()
        self.health.stop()
        self.notifier.stop()
        self.event_log.close()


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
        self._evidence = evidence or FileEvidenceWriter(Path(config.journal.file))
        if sources is None:
            # Lazy import so non-Linux pure tests can inject MemoryObservationSource.
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
        close = getattr(self._evidence, "close", None)
        if callable(close):
            close()

    def request_reload(self) -> None:
        import time

        from .models import ControlMessage

        self._worker.control_sink(
            ControlMessage(kind="reload_request", monotonic_at=time.monotonic())
        )

    def request_shutdown(self, *, force: bool = False) -> None:
        import time

        from .models import ControlMessage

        self._worker.control_sink(
            ControlMessage(
                kind="force_shutdown" if force else "shutdown",
                monotonic_at=time.monotonic(),
            )
        )

    def snapshot(self):
        return self._worker.snapshot()

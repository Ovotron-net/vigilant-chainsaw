from __future__ import annotations

import logging

from .capture import PacketSource
from .config import AppConfig
from .engine import PolicyEngine
from .events import EventDispatcher, Metrics, create_event
from .health import HealthServer
from .models import PacketMetadata


class MonitorService:
    def __init__(self, config: AppConfig, source: PacketSource) -> None:
        self.config = config
        self.source = source
        self.engine = PolicyEngine(config.rules)
        self.metrics = Metrics()
        self.dispatcher = EventDispatcher(config.logging, config.notifications, self.metrics)
        self.health = HealthServer(
            config.health,
            self.metrics,
            rules_provider=self.engine.snapshot,
            events_provider=self.dispatcher.recent_events,
        )

    def start(self) -> None:
        try:
            self.dispatcher.start()
            self.health.start()
            logging.getLogger(__name__).info(
                "Monitoring interface=%s filter=%s",
                self.config.sensor.interface or "default",
                self.config.sensor.bpf_filter,
            )
            # May block until exhaustion for finite sources (PCAP replay).
            # Readiness flips only once the source confirms capture is established.
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
            self.dispatcher.emit(create_event(metadata, rule))

    def reload_rules(self, config: AppConfig) -> None:
        self.engine.replace_rules(config.rules)
        logging.getLogger(__name__).info("Reloaded %d policy rules", len(config.rules))

    def stop(self) -> None:
        self.metrics.set_ready(False)
        self.source.stop()
        self.health.stop()
        self.dispatcher.stop()

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scapy.sendrecv import AsyncSniffer, sniff

from .config import AppConfig
from .engine import PolicyEngine, packet_to_metadata
from .events import EventDispatcher, Metrics, create_event
from .health import HealthServer


class MonitorService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.engine = PolicyEngine(config.rules)
        self.metrics = Metrics()
        self.dispatcher = EventDispatcher(config.logging, config.notifications, self.metrics)
        self.health = HealthServer(config.health, self.metrics)
        self.sniffer: AsyncSniffer | None = None

    def start(self) -> None:
        self.dispatcher.start()
        self.health.start()
        self.sniffer = AsyncSniffer(
            iface=self.config.sensor.interface,
            filter=self.config.sensor.bpf_filter,
            promisc=self.config.sensor.promiscuous,
            prn=self.process_packet,
            store=False,
        )
        self.sniffer.start()
        self.metrics.set_ready(True)
        logging.getLogger(__name__).info(
            "Monitoring interface=%s filter=%s",
            self.config.sensor.interface or "default",
            self.config.sensor.bpf_filter,
        )

    def process_pcap(self, path: str | Path) -> None:
        self.dispatcher.start()
        self.health.start()
        self.metrics.set_ready(True)
        sniff(offline=str(path), prn=self.process_packet, store=False)

    def process_packet(self, packet: Any) -> None:
        metadata = packet_to_metadata(packet)
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
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop(join=True)
        self.health.stop()
        self.dispatcher.stop()

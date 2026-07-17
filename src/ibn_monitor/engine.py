from __future__ import annotations

from ipaddress import ip_address
from threading import RLock

from .models import PacketMetadata, Rule


class PolicyEngine:
    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self._rules = rules
        self._lock = RLock()

    def replace_rules(self, rules: tuple[Rule, ...]) -> None:
        with self._lock:
            self._rules = rules

    def snapshot(self) -> tuple[Rule, ...]:
        with self._lock:
            return self._rules

    def evaluate(self, packet: PacketMetadata) -> list[Rule]:
        source = ip_address(packet.source)
        destination = ip_address(packet.destination)
        matches: list[Rule] = []

        for rule in self.snapshot():
            if not rule.enabled:
                continue
            if rule.protocol != "any" and rule.protocol != packet.protocol:
                continue
            if rule.source_cidrs and not any(
                source.version == network.version and source in network
                for network in rule.source_cidrs
            ):
                continue
            if rule.destination_cidrs and not any(
                destination.version == network.version and destination in network
                for network in rule.destination_cidrs
            ):
                continue
            if rule.destination_ports and packet.destination_port not in rule.destination_ports:
                continue
            matches.append(rule)

        return matches

"""Atomic operations read model for probe metrics and the ops HTTP API."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from .models import (
    EpisodeTransition,
    EvidenceEnvelope,
    OperationalSnapshot,
    PolicyRule,
)


def rule_to_dict(rule: PolicyRule) -> dict[str, Any]:
    ports = (
        "any"
        if rule.match.destination_ports is None
        else sorted(rule.match.destination_ports)
    )
    return {
        "id": rule.id,
        "description": rule.description,
        "enabled": rule.enabled,
        "match": {
            "source_cidrs": [str(n) for n in rule.match.source_cidrs],
            "destination_cidrs": [str(n) for n in rule.match.destination_cidrs],
            "protocol": rule.match.protocol,
            "destination_ports": ports,
        },
        "severity": rule.severity,
        "enforcement": rule.enforcement,
    }


def episode_summary(transition: EpisodeTransition) -> dict[str, Any]:
    key = transition.key
    return {
        "episode_id": transition.episode_id,
        "phase": transition.phase,
        "rule_id": transition.rule.id,
        "severity": transition.rule.severity,
        "enforcement": transition.rule.enforcement,
        "source": str(key.source) if key.source else None,
        "destination": str(key.destination) if key.destination else None,
        "protocol": key.protocol,
        "destination_port": key.destination_port,
        "observation_count": transition.observation_count,
        "observed_bytes": transition.observed_bytes,
        "first_observed_at": transition.first_observed_at.isoformat(),
        "last_observed_at": transition.last_observed_at.isoformat(),
        "close_reason": transition.close_reason,
    }


@dataclass
class PipelineCounters:
    observations: int = 0
    complete: int = 0
    partial: int = 0
    undecodable: int = 0
    matched_observations: int = 0
    rule_matches: int = 0
    episodes_started: int = 0
    episodes_progressed: int = 0
    episodes_closed: int = 0


@dataclass
class ReadModel:
    """Thread-safe projection updated only by the processing worker."""

    recent_maxlen: int = 100
    _lock: Lock = field(default_factory=Lock, repr=False)
    _ops: OperationalSnapshot | None = None
    _rules: tuple[PolicyRule, ...] = ()
    _counters: PipelineCounters = field(default_factory=PipelineCounters)
    _recent_events: deque[dict[str, object]] = field(default_factory=lambda: deque(maxlen=100))
    _events_truncated: bool = False
    _journal_healthy: bool = True
    _notifier_sent: int = 0
    _notifier_failed: int = 0
    _notifier_dropped: int = 0
    _notifier_suppressed: int = 0

    def __post_init__(self) -> None:
        self._recent_events = deque(maxlen=self.recent_maxlen)

    def set_ops(self, snapshot: OperationalSnapshot) -> None:
        with self._lock:
            self._ops = snapshot

    def set_rules(self, rules: tuple[PolicyRule, ...]) -> None:
        with self._lock:
            self._rules = rules

    def note_observation(self, outcome: str, *, matched: bool, rule_matches: int) -> None:
        with self._lock:
            self._counters.observations += 1
            if outcome == "complete":
                self._counters.complete += 1
            elif outcome == "partial":
                self._counters.partial += 1
            else:
                self._counters.undecodable += 1
            if matched:
                self._counters.matched_observations += 1
            self._counters.rule_matches += rule_matches

    def note_phase(self, phase: str) -> None:
        with self._lock:
            if phase == "start":
                self._counters.episodes_started += 1
            elif phase == "progress":
                self._counters.episodes_progressed += 1
            elif phase == "close":
                self._counters.episodes_closed += 1

    def note_envelope(self, envelope: EvidenceEnvelope) -> None:
        with self._lock:
            if len(self._recent_events) == self._recent_events.maxlen:
                self._events_truncated = True
            self._recent_events.append(envelope.to_dict())

    def set_journal_healthy(self, healthy: bool) -> None:
        with self._lock:
            self._journal_healthy = healthy

    def set_notifier_stats(
        self, *, sent: int, failed: int, dropped: int, suppressed: int
    ) -> None:
        with self._lock:
            self._notifier_sent = sent
            self._notifier_failed = failed
            self._notifier_dropped = dropped
            self._notifier_suppressed = suppressed

    def view(
        self,
        *,
        active_episodes: tuple[EpisodeTransition, ...],
    ) -> dict[str, object]:
        with self._lock:
            ops = self._ops
            rules = self._rules
            counters = self._counters
            recent = list(self._recent_events)
            events_truncated = self._events_truncated
            journal_healthy = self._journal_healthy
            notifier = {
                "sent": self._notifier_sent,
                "failed": self._notifier_failed,
                "dropped": self._notifier_dropped,
                "suppressed": self._notifier_suppressed,
            }

        episodes = [episode_summary(item) for item in active_episodes[:100]]
        episodes_truncated = len(active_episodes) > 100
        return {
            "operational": {
                "state": ops.state if ops else "starting",
                "ready": ops.ready if ops else False,
                "reasons": sorted(ops.reasons) if ops else [],
                "policy_revision": ops.policy_revision if ops else None,
                "config_revision": ops.config_revision if ops else None,
                "sensor_id": ops.sensor_id if ops else "",
                "boot_id": ops.boot_id if ops else "",
                "queue_depth": ops.queue_depth if ops else 0,
                "queue_capacity": ops.queue_capacity if ops else 0,
                "app_queue_drops_total": ops.app_queue_drops_total if ops else 0,
                "kernel_drops_total": ops.kernel_drops_total if ops else 0,
                "sources": [
                    {
                        "capture_point": s.capture_point,
                        "interface": s.interface,
                        "state": s.state,
                        "source_generation": s.source_generation,
                        "last_error": s.last_error,
                        "kernel_packets": s.kernel_packets,
                        "kernel_drops": s.kernel_drops,
                    }
                    for s in (ops.sources if ops else ())
                ],
            },
            "totals": {
                "observations": counters.observations,
                "complete": counters.complete,
                "partial": counters.partial,
                "undecodable": counters.undecodable,
                "matched_observations": counters.matched_observations,
                "rule_matches": counters.rule_matches,
                "episodes_started": counters.episodes_started,
                "episodes_progressed": counters.episodes_progressed,
                "episodes_closed": counters.episodes_closed,
            },
            "rules": [rule_to_dict(rule) for rule in rules],
            "active_episodes": episodes,
            "active_episodes_truncated": episodes_truncated,
            "recent_events": recent,
            "recent_events_truncated": events_truncated,
            "journal": {"healthy": journal_healthy},
            "notifier": notifier,
        }

    def metrics_text(self) -> str:
        with self._lock:
            ops = self._ops
            counters = self._counters
            journal_healthy = self._journal_healthy
            notifier_sent = self._notifier_sent
            notifier_failed = self._notifier_failed
            notifier_dropped = self._notifier_dropped

        ready = 1 if ops and ops.ready else 0
        lines = [
            "# HELP ibn_monitor_ready Whether the sensor is fully ready.",
            "# TYPE ibn_monitor_ready gauge",
            f"ibn_monitor_ready {ready}",
            "# HELP ibn_monitor_observations_total Observations processed.",
            "# TYPE ibn_monitor_observations_total counter",
            f"ibn_monitor_observations_total {counters.observations}",
            "# HELP ibn_monitor_matched_observations_total Observations matching ≥1 rule.",
            "# TYPE ibn_monitor_matched_observations_total counter",
            f"ibn_monitor_matched_observations_total {counters.matched_observations}",
            "# HELP ibn_monitor_rule_matches_total Individual rule matches.",
            "# TYPE ibn_monitor_rule_matches_total counter",
            f"ibn_monitor_rule_matches_total {counters.rule_matches}",
            "# HELP ibn_monitor_episodes_started_total Episode start transitions.",
            "# TYPE ibn_monitor_episodes_started_total counter",
            f"ibn_monitor_episodes_started_total {counters.episodes_started}",
            "# HELP ibn_monitor_episodes_closed_total Episode close transitions.",
            "# TYPE ibn_monitor_episodes_closed_total counter",
            f"ibn_monitor_episodes_closed_total {counters.episodes_closed}",
            "# HELP ibn_monitor_queue_depth Observation queue depth.",
            "# TYPE ibn_monitor_queue_depth gauge",
            f"ibn_monitor_queue_depth {ops.queue_depth if ops else 0}",
            "# HELP ibn_monitor_app_queue_drops_total Application queue drops.",
            "# TYPE ibn_monitor_app_queue_drops_total counter",
            f"ibn_monitor_app_queue_drops_total {ops.app_queue_drops_total if ops else 0}",
            "# HELP ibn_monitor_kernel_drops_total Kernel packet drops.",
            "# TYPE ibn_monitor_kernel_drops_total counter",
            f"ibn_monitor_kernel_drops_total {ops.kernel_drops_total if ops else 0}",
            "# HELP ibn_monitor_journal_healthy Journal writer health.",
            "# TYPE ibn_monitor_journal_healthy gauge",
            f"ibn_monitor_journal_healthy {1 if journal_healthy else 0}",
            "# HELP ibn_monitor_webhook_sent_total Webhook deliveries.",
            "# TYPE ibn_monitor_webhook_sent_total counter",
            f"ibn_monitor_webhook_sent_total {notifier_sent}",
            "# HELP ibn_monitor_webhook_failed_total Webhook failures.",
            "# TYPE ibn_monitor_webhook_failed_total counter",
            f"ibn_monitor_webhook_failed_total {notifier_failed}",
            "# HELP ibn_monitor_webhook_dropped_total Webhook queue drops.",
            "# TYPE ibn_monitor_webhook_dropped_total counter",
            f"ibn_monitor_webhook_dropped_total {notifier_dropped}",
            "",
        ]
        if ops:
            for source in ops.sources:
                point = source.capture_point
                lines.extend(
                    [
                        "# TYPE ibn_monitor_source_kernel_drops_total counter",
                        f'ibn_monitor_source_kernel_drops_total{{capture_point="{point}"}} '
                        f"{source.kernel_drops}",
                    ]
                )
        lines.append("")
        return "\n".join(lines)

from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Protocol

from .config import LoggingConfig, NotificationConfig
from .models import Event, PacketMetadata, Rule

SEVERITY_ORDER = {"low": 10, "medium": 20, "high": 30, "critical": 40}


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.ready = False
        self.packets_seen = 0
        self.packets_decoded = 0
        self.violations = 0
        self.notifications_sent = 0
        self.notification_failures = 0
        self.notifications_suppressed = 0
        self.notification_queue_dropped = 0
        self.last_packet_at = 0.0
        self.last_violation_at = 0.0

    def set_ready(self, value: bool) -> None:
        with self._lock:
            self.ready = value

    def mark_packet(self, *, decoded: bool) -> None:
        with self._lock:
            self.packets_seen += 1
            if decoded:
                self.packets_decoded += 1
            self.last_packet_at = time.time()

    def mark_violation(self) -> None:
        with self._lock:
            self.violations += 1
            self.last_violation_at = time.time()

    def incr_notifications_sent(self, n: int = 1) -> None:
        with self._lock:
            self.notifications_sent += n

    def incr_notification_failures(self, n: int = 1) -> None:
        with self._lock:
            self.notification_failures += n

    def incr_notifications_suppressed(self, n: int = 1) -> None:
        with self._lock:
            self.notifications_suppressed += n

    def incr_notification_queue_dropped(self, n: int = 1) -> None:
        with self._lock:
            self.notification_queue_dropped += n

    def snapshot(self) -> dict[str, int | float | bool]:
        with self._lock:
            return {
                "started_at": self.started_at,
                "ready": self.ready,
                "packets_seen": self.packets_seen,
                "packets_decoded": self.packets_decoded,
                "violations": self.violations,
                "notifications_sent": self.notifications_sent,
                "notification_failures": self.notification_failures,
                "notifications_suppressed": self.notifications_suppressed,
                "notification_queue_dropped": self.notification_queue_dropped,
                "last_packet_at": self.last_packet_at,
                "last_violation_at": self.last_violation_at,
            }


class JsonEventLogger:
    def __init__(self, config: LoggingConfig) -> None:
        path = Path(config.file)
        path.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("ibn_monitor.events")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._logger.handlers.clear()

        file_handler = RotatingFileHandler(
            path,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(console_handler)

    def write(self, event: dict[str, Any]) -> None:
        self._logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))

    def close(self) -> None:
        for handler in tuple(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)


def create_event(packet: PacketMetadata, rule: Rule) -> Event:
    return Event(
        schema_version=1,
        event_id=str(uuid.uuid4()),
        event_type="network_policy_violation",
        observed_at=packet.timestamp,
        rule_id=rule.id,
        rule_description=rule.description,
        rule_severity=rule.severity,
        rule_action=rule.action,
        network=packet,
    )


class Notifier(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def notify(self, event: Event) -> None: ...


class NullNotifier:
    """No-op when webhook_url_env is unset or empty."""

    def start(self) -> None:
        return

    def stop(self) -> None:
        return

    def notify(self, event: Event) -> None:
        return


class WebhookNotifier:
    def __init__(self, config: NotificationConfig, metrics: Metrics) -> None:
        self._notification_config = config
        self._metrics = metrics
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=1000)
        self._thread = threading.Thread(
            target=self._worker,
            name="ibn-webhook-dispatcher",
            daemon=True,
        )
        self._last_sent: dict[str, float] = {}
        self._started = False
        self._stop_event = threading.Event()

    def start(self) -> None:
        if not self._started:
            self._thread.start()
            self._started = True

    def notify(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._metrics.incr_notification_queue_dropped()
            logging.getLogger(__name__).error("Webhook queue is full; notification dropped")

    def stop(self) -> None:
        if self._started:
            self._stop_event.set()
            # Best-effort wake-up; queued notifications are discarded on stop.
            with contextlib.suppress(queue.Full):
                self._queue.put_nowait(None)
            self._thread.join(timeout=5)

    def _webhook_url(self) -> str | None:
        variable = self._notification_config.webhook_url_env
        return os.getenv(variable) if variable else None

    def _worker(self) -> None:
        while True:
            try:
                event = self._queue.get(timeout=0.1)
            except queue.Empty:
                if self._stop_event.is_set():
                    return
                continue
            if event is None or self._stop_event.is_set():
                return
            self._send_if_required(event)

    def _send_if_required(self, event: Event) -> None:
        minimum = self._notification_config.minimum_severity
        if SEVERITY_ORDER[event.rule_severity] < SEVERITY_ORDER[minimum]:
            return

        key = ":".join(
            str(value)
            for value in (
                event.rule_id,
                event.network.source,
                event.network.destination,
                event.network.protocol,
                event.network.destination_port,
            )
        )
        now = time.monotonic()
        window = self._notification_config.deduplication_seconds
        last_sent = self._last_sent.get(key, 0.0)
        if now - last_sent < window:
            self._metrics.incr_notifications_suppressed()
            return
        # Prune expired dedup entries so unique flow keys don't accumulate forever.
        if len(self._last_sent) > 10_000:
            self._last_sent = {
                entry_key: sent_at
                for entry_key, sent_at in self._last_sent.items()
                if now - sent_at < window
            }

        url = self._webhook_url()
        if not url:
            return
        request = urllib.request.Request(
            url,
            data=json.dumps(event.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._notification_config.timeout_seconds,
            ) as response:
                if response.status < 200 or response.status >= 300:
                    raise urllib.error.HTTPError(
                        url,
                        response.status,
                        "Unexpected webhook response",
                        response.headers,
                        None,
                    )
            self._last_sent[key] = now
            self._metrics.incr_notifications_sent()
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            self._metrics.incr_notification_failures()
            logging.getLogger(__name__).error("Webhook delivery failed: %s", exc)


class EventLog:
    def __init__(self, logging_config: LoggingConfig, *, recent_maxlen: int = 50) -> None:
        self._event_logger = JsonEventLogger(logging_config)
        self._recent_lock = threading.Lock()
        self._recent: deque[dict[str, Any]] = deque(maxlen=recent_maxlen)

    def write(self, event: Event) -> None:
        """Append JSONL via JsonEventLogger and push event.to_dict() to recent ring."""
        payload = event.to_dict()
        self._event_logger.write(payload)
        with self._recent_lock:
            self._recent.append(payload)

    def recent(self) -> list[dict[str, object]]:
        with self._recent_lock:
            return list(self._recent)

    def close(self) -> None:
        self._event_logger.close()


def build_notifier(config: NotificationConfig, metrics: Metrics) -> Notifier:
    """Return NullNotifier if webhook_url_env is unset/None; else WebhookNotifier."""
    if not config.webhook_url_env:
        return NullNotifier()
    return WebhookNotifier(config, metrics)

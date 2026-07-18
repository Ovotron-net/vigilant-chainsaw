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
from dataclasses import asdict
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .config import LoggingConfig, NotificationConfig
from .models import PacketMetadata, Rule

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

    def update(self, **increments: int) -> None:
        with self._lock:
            for key, value in increments.items():
                setattr(self, key, int(getattr(self, key)) + value)

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


def create_event(packet: PacketMetadata, rule: Rule) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid4()),
        "event_type": "network_policy_violation",
        "observed_at": packet.timestamp,
        "rule": {
            "id": rule.id,
            "description": rule.description,
            "severity": rule.severity,
            "action": rule.action,
        },
        "network": asdict(packet),
    }


class EventDispatcher:
    def __init__(
        self,
        logging_config: LoggingConfig,
        notification_config: NotificationConfig,
        metrics: Metrics,
    ) -> None:
        self._event_logger = JsonEventLogger(logging_config)
        self._notification_config = notification_config
        self._metrics = metrics
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=1000)
        self._thread = threading.Thread(
            target=self._worker,
            name="ibn-webhook-dispatcher",
            daemon=True,
        )
        self._last_sent: dict[str, float] = {}
        self._started = False
        self._recent_lock = threading.Lock()
        self._recent: deque[dict[str, Any]] = deque(maxlen=50)

    def start(self) -> None:
        if not self._started:
            self._thread.start()
            self._started = True

    def recent_events(self) -> list[dict[str, Any]]:
        with self._recent_lock:
            return list(self._recent)

    def emit(self, event: dict[str, Any]) -> None:
        self._event_logger.write(event)
        with self._recent_lock:
            self._recent.append(event)
        if not self._webhook_url():
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._metrics.update(notification_queue_dropped=1)
            logging.getLogger(__name__).error("Webhook queue is full; notification dropped")

    def stop(self) -> None:
        if self._started:
            # Blocking put with a timeout so the sentinel isn't lost when the
            # queue is momentarily full; the worker drains it within the wait.
            with contextlib.suppress(queue.Full):
                self._queue.put(None, timeout=2)
            self._thread.join(timeout=5)
        self._event_logger.close()

    def _webhook_url(self) -> str | None:
        variable = self._notification_config.webhook_url_env
        return os.getenv(variable) if variable else None

    def _worker(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            self._send_if_required(event)

    def _send_if_required(self, event: dict[str, Any]) -> None:
        severity = str(event["rule"]["severity"])
        minimum = self._notification_config.minimum_severity
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[minimum]:
            return

        network = event["network"]
        key = ":".join(
            str(value)
            for value in (
                event["rule"]["id"],
                network["source"],
                network["destination"],
                network["protocol"],
                network["destination_port"],
            )
        )
        now = time.monotonic()
        window = self._notification_config.deduplication_seconds
        last_sent = self._last_sent.get(key, 0.0)
        if now - last_sent < window:
            self._metrics.update(notifications_suppressed=1)
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
            data=json.dumps(event).encode("utf-8"),
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
            self._metrics.update(notifications_sent=1)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            self._metrics.update(notification_failures=1)
            logging.getLogger(__name__).error("Webhook delivery failed: %s", exc)

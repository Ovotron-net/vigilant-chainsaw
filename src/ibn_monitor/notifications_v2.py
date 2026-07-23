"""V2 webhook notifier for sequenced EvidenceEnvelope events."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import random
import threading
import time
import urllib.error
import urllib.request
from typing import Protocol
from urllib.parse import urlparse

from .config import NotificationV2Config
from .models import EpisodeTransition, EvidenceEnvelope, SystemPayload

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 10, "medium": 20, "high": 30, "critical": 40}


class V2Notifier(Protocol):
    def start(self) -> None: ...
    def stop(self, *, drain_seconds: float = 5.0) -> None: ...
    def notify(self, envelope: EvidenceEnvelope) -> None: ...


class NullV2Notifier:
    def start(self) -> None:
        return

    def stop(self, *, drain_seconds: float = 5.0) -> None:
        return

    def notify(self, envelope: EvidenceEnvelope) -> None:
        return


class WebhookV2Notifier:
    def __init__(self, config: NotificationV2Config) -> None:
        self._config = config
        self._url = self._resolve_url()
        self._queue: queue.Queue[EvidenceEnvelope | None] = queue.Queue(maxsize=1000)
        self._thread = threading.Thread(
            target=self._worker, name="ibn-webhook-v2", daemon=True
        )
        self._started = False
        self._stop = threading.Event()
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.suppressed = 0

    def _resolve_url(self) -> str | None:
        if not self._config.webhook_url_env:
            return None
        url = os.getenv(self._config.webhook_url_env)
        if not url:
            return None
        parsed = urlparse(url)
        if parsed.fragment or parsed.username or parsed.password:
            raise ValueError("webhook URL must not include credentials or fragments")
        if parsed.scheme == "https":
            return url
        if (
            parsed.scheme == "http"
            and self._config.insecure_allow_http_loopback
            and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        ):
            return url
        raise ValueError("webhook URL must be https (or http loopback with insecure flag)")

    def start(self) -> None:
        if not self._url:
            return
        if not self._started:
            self._thread.start()
            self._started = True

    def notify(self, envelope: EvidenceEnvelope) -> None:
        if not self._url or not self._eligible(envelope):
            self.suppressed += 1
            return
        try:
            self._queue.put_nowait(envelope)
        except queue.Full:
            self.dropped += 1
            logger.error("v2 webhook queue full; drop %s", envelope.event_id)

    def stop(self, *, drain_seconds: float = 5.0) -> None:
        if not self._started:
            return
        deadline = time.monotonic() + drain_seconds
        while time.monotonic() < deadline and not self._queue.empty():
            time.sleep(0.05)
        self._stop.set()
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)
        self._thread.join(timeout=2)

    def _eligible(self, envelope: EvidenceEnvelope) -> bool:
        payload = envelope.payload
        if isinstance(payload, EpisodeTransition):
            if payload.phase not in {"start", "close"}:
                return False
            return (
                SEVERITY_ORDER[payload.rule.severity]
                >= SEVERITY_ORDER[self._config.minimum_severity]
            )
        if isinstance(payload, SystemPayload):
            return payload.name in {
                "coverage_gap",
                "kernel_drops_observed",
                "source_failed",
                "policy_reload_failed",
            }
        return False

    def _worker(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.1)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            if item is None or self._stop.is_set():
                return
            self._deliver(item)

    def _deliver(self, envelope: EvidenceEnvelope) -> None:
        assert self._url is not None
        body = json.dumps(envelope.to_dict(), separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        attempts = 0
        started = time.monotonic()
        delay = 0.2
        while attempts < self._config.max_attempts:
            if time.monotonic() - started > self._config.max_elapsed_seconds:
                break
            attempts += 1
            request = urllib.request.Request(
                self._url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Idempotency-Key": envelope.event_id,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=self._config.timeout_seconds
                ) as response:
                    if 200 <= response.status < 300:
                        self.sent += 1
                        return
                    raise urllib.error.HTTPError(
                        self._url, response.status, "bad status", response.headers, None
                    )
            except urllib.error.HTTPError as exc:
                if exc.code in {301, 302, 303, 307, 308}:
                    # Reject cross-origin redirects by refusing to follow.
                    self.failed += 1
                    logger.error("webhook redirect rejected for %s", envelope.event_id)
                    return
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after and retry_after.isdigit():
                    time.sleep(min(float(retry_after), 30.0))
                else:
                    time.sleep(delay + random.uniform(0, delay * 0.25))
                    delay = min(delay * 2, 8.0)
            except (OSError, urllib.error.URLError):
                time.sleep(delay + random.uniform(0, delay * 0.25))
                delay = min(delay * 2, 8.0)
        self.failed += 1
        logger.error("webhook exhausted retries for %s", envelope.event_id)


def build_v2_notifier(config: NotificationV2Config) -> V2Notifier:
    if not config.webhook_url_env:
        return NullV2Notifier()
    return WebhookV2Notifier(config)

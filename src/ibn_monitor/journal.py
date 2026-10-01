"""Durable schema-v2 evidence journal (Phase 3).

Sequence numbers remain allocated by EvidenceSequencer on the processing worker.
This module owns append durability, rotation, fsync cadence, and emergency buffering.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path

from .config import JournalV2Config
from .evidence import serialize_evidence
from .models import EvidenceEnvelope

logger = logging.getLogger(__name__)


class JournalWriter:
    """Append-only JSONL with rotation, fsync, and emergency buffer."""

    def __init__(self, config: JournalV2Config) -> None:
        self._config = config
        self._path = Path(config.file)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._handle = self._path.open("a", encoding="utf-8")
        self._bytes_since_fsync = 0
        self._last_fsync = time.monotonic()
        self._healthy = True
        self._emergency: deque[str] = deque()
        self._emergency_bytes = 0
        self._emergency_dropped = 0
        self._unclean_boot = self._detect_unclean_boot()
        self._clean_shutdown_allowed = True

    @property
    def healthy(self) -> bool:
        return self._healthy

    @property
    def unclean_boot(self) -> bool:
        return self._unclean_boot

    @property
    def emergency_dropped(self) -> int:
        return self._emergency_dropped

    def _detect_unclean_boot(self) -> bool:
        marker = self._path.with_suffix(self._path.suffix + ".clean")
        if not self._path.exists():
            return False
        # Missing clean-stop marker after an existing journal ⇒ unclean prior exit.
        return not marker.exists() and self._path.stat().st_size > 0

    def _mark_running(self) -> None:
        marker = self._path.with_suffix(self._path.suffix + ".clean")
        marker.unlink(missing_ok=True)

    def _mark_clean(self) -> None:
        marker = self._path.with_suffix(self._path.suffix + ".clean")
        marker.write_text("ok\n", encoding="utf-8")

    def commit(self, envelope: EvidenceEnvelope) -> None:
        line = serialize_evidence(envelope) + "\n"
        with self._lock:
            self._mark_running()
            if not self._healthy:
                self._buffer(line)
                return
            try:
                self._write_line(line)
                self._maybe_fsync()
                self._maybe_rotate()
                self._drain_emergency()
            except OSError as exc:
                logger.error("journal write failed: %s", exc)
                self._healthy = False
                self._buffer(line)

    def maintain(self) -> None:
        """Run periodic durability and recovery work from the pipeline timer."""
        with self._lock:
            if not self._healthy:
                self._try_recover_locked()
                return
            if (
                self._bytes_since_fsync
                and time.monotonic() - self._last_fsync >= self._config.fsync_interval_seconds
            ):
                try:
                    self._sync()
                except OSError as exc:
                    logger.error("journal fsync failed: %s", exc)
                    self._healthy = False

    def flush(self, *, mark_clean: bool = True) -> None:
        with self._lock:
            self._clean_shutdown_allowed = self._clean_shutdown_allowed and mark_clean
            if self._healthy:
                try:
                    self._drain_emergency()
                    self._sync()
                except OSError as exc:
                    logger.error("journal fsync failed: %s", exc)
                    self._healthy = False
            if self._clean_shutdown_allowed and self._healthy and not self._emergency:
                self._mark_clean()
            else:
                self._mark_running()

    def close(self) -> None:
        with self._lock:
            try:
                if self._healthy:
                    self._drain_emergency()
                    self._sync()
                self._handle.close()
            except OSError as exc:
                logger.error("journal close failed: %s", exc)
                self._healthy = False
            if self._clean_shutdown_allowed and self._healthy and not self._emergency:
                self._mark_clean()
            else:
                self._mark_running()

    def _write_line(self, line: str) -> None:
        encoded = line.encode("utf-8")
        self._handle.write(line)
        self._bytes_since_fsync += len(encoded)

    def _maybe_fsync(self) -> None:
        now = time.monotonic()
        if now - self._last_fsync >= self._config.fsync_interval_seconds:
            self._sync(now=now)

    def _sync(self, *, now: float | None = None) -> None:
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._last_fsync = time.monotonic() if now is None else now
        self._bytes_since_fsync = 0

    def _maybe_rotate(self) -> None:
        self._handle.flush()
        size = self._path.stat().st_size
        if size < self._config.max_bytes:
            return
        # A rotated segment will never be touched by a later cadence fsync.
        self._sync()
        self._handle.close()
        # Rotate: file.(n-1) -> file.n, then file -> file.1
        for index in range(self._config.backup_count - 1, 0, -1):
            src = Path(f"{self._path}.{index}")
            dst = Path(f"{self._path}.{index + 1}")
            if src.exists():
                src.replace(dst)
        if self._path.exists():
            self._path.replace(Path(f"{self._path}.1"))
        self._handle = self._path.open("a", encoding="utf-8")

    def _buffer(self, line: str) -> None:
        encoded_len = len(line.encode("utf-8"))
        while (
            len(self._emergency) >= self._config.emergency_max_events
            or self._emergency_bytes + encoded_len > self._config.emergency_max_bytes
        ) and self._emergency:
            dropped = self._emergency.popleft()
            self._emergency_bytes -= len(dropped.encode("utf-8"))
            self._emergency_dropped += 1
        self._emergency.append(line)
        self._emergency_bytes += encoded_len

    def _drain_emergency(self) -> None:
        if not self._emergency:
            return
        while self._emergency:
            line = self._emergency[0]
            self._write_line(line)
            self._emergency.popleft()
            self._emergency_bytes -= len(line.encode("utf-8"))
        self._maybe_fsync()

    def try_recover(self) -> bool:
        """Attempt to reopen the journal after a failure."""
        with self._lock:
            return self._try_recover_locked()

    def _try_recover_locked(self) -> bool:
        if self._healthy:
            return True
        try:
            with contextlib.suppress(OSError):
                self._handle.close()
            self._handle = self._path.open("a", encoding="utf-8")
            self._healthy = True
            self._drain_emergency()
            self._sync()
            return True
        except OSError as exc:
            self._healthy = False
            logger.error("journal recovery failed: %s", exc)
            return False

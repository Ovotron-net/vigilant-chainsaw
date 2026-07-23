"""Durable schema-v2 evidence journal (Phase 3).

Sequence numbers remain allocated by EvidenceSequencer on the processing worker.
This module owns append durability, rotation, fsync cadence, and emergency buffering.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .events import serialize_evidence
from .models import EvidenceEnvelope

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class JournalConfig:
    file: str
    max_bytes: int = 10_485_760
    backup_count: int = 5
    fsync_interval_seconds: float = 1.0
    emergency_max_events: int = 1_000
    emergency_max_bytes: int = 8_388_608


class JournalWriter:
    """Append-only JSONL with rotation, fsync, and emergency buffer."""

    def __init__(self, config: JournalConfig) -> None:
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

    def flush(self) -> None:
        with self._lock:
            if self._healthy:
                try:
                    self._handle.flush()
                    self._handle.fileno()  # ensure open
                    import os

                    os.fsync(self._handle.fileno())
                    self._last_fsync = time.monotonic()
                    self._bytes_since_fsync = 0
                except OSError as exc:
                    logger.error("journal fsync failed: %s", exc)
                    self._healthy = False
            self._mark_clean()

    def close(self) -> None:
        with self._lock:
            try:
                if self._healthy:
                    self._handle.flush()
                    import os

                    os.fsync(self._handle.fileno())
                self._handle.close()
            except OSError:
                pass
            self._mark_clean()

    def _write_line(self, line: str) -> None:
        encoded = line.encode("utf-8")
        self._handle.write(line)
        self._bytes_since_fsync += len(encoded)

    def _maybe_fsync(self) -> None:
        now = time.monotonic()
        if now - self._last_fsync >= self._config.fsync_interval_seconds:
            self._handle.flush()
            import os

            os.fsync(self._handle.fileno())
            self._last_fsync = now
            self._bytes_since_fsync = 0

    def _maybe_rotate(self) -> None:
        self._handle.flush()
        size = self._path.stat().st_size
        if size < self._config.max_bytes:
            return
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
            if self._healthy:
                return True
            try:
                self._handle = self._path.open("a", encoding="utf-8")
                self._healthy = True
                self._drain_emergency()
                self._maybe_fsync()
                return True
            except OSError as exc:
                logger.error("journal recovery failed: %s", exc)
                return False

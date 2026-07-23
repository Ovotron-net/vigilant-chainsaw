from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .events import serialize_evidence
from .models import EvidenceEnvelope


class EvidenceWriter(Protocol):
    def commit(self, envelope: EvidenceEnvelope) -> None:
        """Append an already-sequenced envelope in processing order."""
        ...

    def flush(self) -> None: ...


class MemoryEvidenceWriter:
    def __init__(self) -> None:
        self.events: list[EvidenceEnvelope] = []

    def commit(self, envelope: EvidenceEnvelope) -> None:
        self.events.append(envelope)

    def flush(self) -> None:
        return


class FileEvidenceWriter:
    """Append-only JSONL; no rotation/fsync/emergency (Phase 3)."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self._path.open("a", encoding="utf-8")

    def commit(self, envelope: EvidenceEnvelope) -> None:
        self._handle.write(serialize_evidence(envelope) + "\n")

    def flush(self) -> None:
        self._handle.flush()

    def close(self) -> None:
        self.flush()
        self._handle.close()

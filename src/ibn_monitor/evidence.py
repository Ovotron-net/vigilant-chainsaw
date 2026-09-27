"""Evidence envelope sequencing and canonical JSONL serialization (schema v2)."""

from __future__ import annotations

import json
import re
from datetime import datetime

from .models import EpisodeTransition, EvidenceEnvelope, SystemEventName, SystemPayload

MAX_EVIDENCE_LINE_BYTES = 262_144
_SYSTEM_FIELD_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_SYSTEM_NAMES: frozenset[str] = frozenset(
    {
        "sensor_start",
        "sensor_stopping",
        "sensor_stop",
        "source_established",
        "source_failed",
        "source_retrying",
        "source_recovered",
        "source_stopped",
        "policy_reload_success",
        "policy_reload_noop",
        "policy_reload_failed",
        "coverage_gap",
        "kernel_drops_observed",
    }
)


class EvidenceSequencer:
    def __init__(self, sensor_id: str, boot_id: str) -> None:
        self._sensor_id = sensor_id
        self._boot_id = boot_id
        self._next_sequence = 1

    def wrap_episode(
        self,
        transition: EpisodeTransition,
        *,
        emitted_at: datetime,
    ) -> EvidenceEnvelope:
        sequence = self._next_sequence
        self._next_sequence += 1
        return EvidenceEnvelope(
            schema_version=2,
            event_id=f"{self._boot_id}:{sequence}",
            event_type="violation_episode",
            sensor_id=self._sensor_id,
            boot_id=self._boot_id,
            sequence=sequence,
            emitted_at=emitted_at,
            policy_revision=transition.key.policy_revision,
            payload=transition,
        )

    def wrap_system(
        self,
        name: SystemEventName,
        fields: dict[str, object],
        *,
        emitted_at: datetime,
        policy_revision: str | None,
    ) -> EvidenceEnvelope:
        if name not in _SYSTEM_NAMES:
            raise ValueError(f"unknown system event name: {name}")
        if len(fields) > 32:
            raise ValueError("system payload may not exceed 32 fields")
        for key, value in fields.items():
            if not _SYSTEM_FIELD_KEY.match(key):
                raise ValueError(f"invalid system field key: {key}")
            if not _is_json_scalar(value):
                raise ValueError(f"system field {key} is not JSON-serializable")
        if name.startswith("policy_reload_") and policy_revision is None:
            raise ValueError("policy_reload events require policy_revision")
        sequence = self._next_sequence
        self._next_sequence += 1
        envelope = EvidenceEnvelope(
            schema_version=2,
            event_id=f"{self._boot_id}:{sequence}",
            event_type=f"system.{name}",
            sensor_id=self._sensor_id,
            boot_id=self._boot_id,
            sequence=sequence,
            emitted_at=emitted_at,
            policy_revision=policy_revision,
            payload=SystemPayload(name=name, fields=dict(fields)),
        )
        # Enforce size bound early.
        serialize_evidence(envelope)
        return envelope


def _is_json_scalar(value: object) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_is_json_scalar(item) for item in value) and len(value) <= 64
    return False


def _serialize_evidence_dict(payload: dict[str, object]) -> str:
    line = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len((line + "\n").encode("utf-8")) > MAX_EVIDENCE_LINE_BYTES:
        raise ValueError("evidence event exceeds 262144 bytes")
    return line


def serialize_evidence(event: EvidenceEnvelope) -> str:
    return _serialize_evidence_dict(event.to_dict())

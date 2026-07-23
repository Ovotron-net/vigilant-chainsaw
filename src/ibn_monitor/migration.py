from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .config import Topology
from .models import Diagnostic


@dataclass(frozen=True, slots=True)
class MigrationRequest:
    sensor_id: str
    topology: Topology
    capture_point_name: str
    interface: str


@dataclass(frozen=True, slots=True)
class MigrationResult:
    payload: dict[str, object] | None
    diagnostics: tuple[Diagnostic, ...]

    @property
    def valid(self) -> bool:
        return self.payload is not None and not any(
            item.severity == "error" for item in self.diagnostics
        )


def _migrate_rule(
    rule: dict[str, Any],
    index: int,
) -> tuple[dict[str, object] | None, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    for field in ("source_cidrs", "destination_cidrs"):
        if not rule.get(field):
            diagnostics.append(
                Diagnostic(
                    "error",
                    f"migration.ambiguous_{field}",
                    f"/rules/{index}/{field}",
                    f"v1 omitted/empty {field} meant any; write explicit /0 networks",
                )
            )
    protocol = str(rule.get("protocol", "any")).lower()
    if protocol in {"tcp", "udp"} and not rule.get("destination_ports"):
        diagnostics.append(
            Diagnostic(
                "error",
                "migration.ambiguous_destination_ports",
                f"/rules/{index}/destination_ports",
                'v1 omitted/empty ports meant any; choose "any" or explicit ports',
            )
        )
    if diagnostics:
        return None, diagnostics

    match: dict[str, object] = {
        "source_cidrs": list(rule["source_cidrs"]),
        "destination_cidrs": list(rule["destination_cidrs"]),
        "protocol": protocol,
    }
    if protocol in {"tcp", "udp"}:
        match["destination_ports"] = list(rule["destination_ports"])
    migrated = {
        "id": rule["id"],
        "description": rule.get("description", rule["id"]),
        "enabled": rule.get("enabled", True),
        "match": match,
        "severity": str(rule.get("severity", "high")).lower(),
        "enforcement": (
            "nftables_drop_candidate"
            if str(rule.get("action", "alert")).lower() == "drop"
            else "none"
        ),
    }
    return migrated, diagnostics


def migrate_v1_policy(raw: object, request: MigrationRequest) -> MigrationResult:
    diagnostics: list[Diagnostic] = []
    if not isinstance(raw, dict):
        return MigrationResult(
            None,
            (
                Diagnostic(
                    "error",
                    "migration.invalid_root",
                    "/",
                    "v1 policy root must be an object",
                ),
            ),
        )

    data = cast_dict(raw)
    sensor = cast_dict(data.get("sensor", {}))
    bpf_filter = sensor.get("bpf_filter", "ip or ip6")
    if bpf_filter not in (None, "ip or ip6"):
        diagnostics.append(
            Diagnostic(
                "error",
                "migration.unsupported_bpf_filter",
                "/sensor/bpf_filter",
                "v2 does not accept free-form BPF filters",
            )
        )

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        diagnostics.append(
            Diagnostic(
                "error",
                "migration.invalid_rules",
                "/rules",
                "rules must be an array",
            )
        )
        return MigrationResult(None, tuple(diagnostics))

    migrated_rules: list[dict[str, object]] = []
    for index, rule_value in enumerate(rules_raw):
        if not isinstance(rule_value, dict):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "migration.invalid_rule",
                    f"/rules/{index}",
                    "rule must be an object",
                )
            )
            continue
        migrated, rule_diagnostics = _migrate_rule(rule_value, index)
        diagnostics.extend(rule_diagnostics)
        if migrated is not None:
            migrated_rules.append(migrated)

    if any(item.severity == "error" for item in diagnostics):
        return MigrationResult(None, tuple(diagnostics))

    direction = "both" if request.topology == "host" else "inbound"
    promiscuous = True if request.topology == "mirror" else bool(sensor.get("promiscuous", False))

    payload: dict[str, object] = {
        "version": 2,
        "sensor": {
            "id": request.sensor_id,
            "topology": request.topology,
            "capture_points": [
                {
                    "name": request.capture_point_name,
                    "interface": request.interface,
                    "direction": direction,
                    "promiscuous": promiscuous,
                }
            ],
        },
        "rules": migrated_rules,
    }

    logging = cast_dict(data.get("logging", {}))
    journal: dict[str, object] = {}
    if "file" in logging:
        journal["file"] = logging["file"]
    if "max_bytes" in logging:
        journal["max_bytes"] = logging["max_bytes"]
    if "backup_count" in logging:
        journal["backup_count"] = logging["backup_count"]
    if journal:
        payload["journal"] = journal

    health = cast_dict(data.get("health", {}))
    http: dict[str, object] = {}
    probe: dict[str, object] = {}
    if "enabled" in health:
        probe["enabled"] = health["enabled"]
    if "bind" in health:
        probe["bind"] = health["bind"]
    if "port" in health:
        probe["port"] = health["port"]
    if probe:
        http["probe"] = probe
    if "enabled" in health:
        http["operations"] = {"enabled": health["enabled"]}
    if http:
        payload["http"] = http

    notifications_raw = cast_dict(data.get("notifications", {}))
    notifications: dict[str, object] = {}
    for key in ("webhook_url_env", "timeout_seconds", "minimum_severity"):
        if key in notifications_raw:
            notifications[key] = notifications_raw[key]
    if notifications:
        payload["notifications"] = notifications

    return MigrationResult(copy.deepcopy(payload), tuple(diagnostics))


def cast_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}

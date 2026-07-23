#!/usr/bin/env python3
"""Cross-platform pipeline microbench (not the full Linux AF_PACKET gate).

Measures MemoryObservationSource → PipelineWorker → MemoryEvidenceWriter
throughput for synthetic TCP observations against a compiled policy.

Usage:
  python scripts/microbench_pipeline.py
  python scripts/microbench_pipeline.py --observations 50000 --write build/microbench.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dataclasses import replace  # noqa: E402

from ibn_monitor.capture import MemoryObservationSource  # noqa: E402
from ibn_monitor.config import (  # noqa: E402
    canonical_config_revision,
    canonical_policy_revision,
    load_v2_config,
)
from ibn_monitor.evidence_stub import MemoryEvidenceWriter  # noqa: E402
from ibn_monitor.models import FieldPresence, Observation, PolicyMatch, PolicyRule  # noqa: E402
from ibn_monitor.monitor import LiveMonitor  # noqa: E402


def _make_observation(i: int, sensor_id: str) -> Observation:
    return Observation(
        captured_at=datetime.now(UTC),
        monotonic_at=time.monotonic(),
        sensor_id=sensor_id,
        source_generation="bench",
        capture_point="wan",
        interface="bench0",
        direction="unknown",
        wire_length=60,
        ip_version=4,
        source=ip_address("10.20.5.14"),
        destination=ip_address("10.50.10.8"),
        protocol="tcp",
        source_port=40000 + (i % 1000),
        destination_port=5432,
        tcp_flags=0x02,
        fields=FieldPresence.complete_tcp(),
        outcome="complete",
    )


def _expand_rules(base: tuple[PolicyRule, ...], count: int) -> tuple[PolicyRule, ...]:
    if count <= len(base):
        return base[:count]
    rules = list(base)
    template = base[0]
    while len(rules) < count:
        idx = len(rules)
        rules.append(
            PolicyRule(
                id=f"BENCH-{idx:03d}",
                description=template.description,
                enabled=True,
                match=PolicyMatch(
                    source_cidrs=template.match.source_cidrs,
                    destination_cidrs=template.match.destination_cidrs,
                    protocol=template.match.protocol,
                    destination_ports=template.match.destination_ports,
                ),
                severity=template.severity,
                enforcement="none",
            )
        )
    return tuple(rules)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", type=int, default=20_000)
    parser.add_argument("--rules", type=int, default=1)
    parser.add_argument("--write", type=Path, help="Write JSON summary")
    args = parser.parse_args()

    example = ROOT / "config" / "policy.v2.example.json"
    config = load_v2_config(example)
    rules = _expand_rules(config.rules, args.rules)
    provisional = replace(
        config,
        rules=rules,
        policy_revision=canonical_policy_revision(rules),
        config_revision="",
    )
    config = replace(
        provisional, config_revision=canonical_config_revision(provisional)
    )

    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_path=str(example),
        sources=(source,),
        evidence=evidence,
        boot_id="microbench",
        probe_enabled=False,
        operations_enabled=False,
    )

    latencies: list[float] = []
    monitor.start()
    try:
        time.sleep(0.05)
        t0 = time.perf_counter()
        for i in range(args.observations):
            before = time.perf_counter()
            source.push(_make_observation(i, config.sensor.id))
            latencies.append(time.perf_counter() - before)
        deadline = time.time() + 30
        view: dict = {}
        while time.time() < deadline:
            view = monitor.operations_state()
            if view["totals"]["observations"] >= args.observations:
                break
            time.sleep(0.05)
        elapsed = time.perf_counter() - t0
        view = monitor.operations_state()
    finally:
        monitor.stop()

    processed = int(view["totals"]["observations"])
    rate = processed / elapsed if elapsed > 0 else 0.0
    if len(latencies) >= 100:
        p99 = statistics.quantiles(latencies, n=100)[98] * 1000
    else:
        p99 = max(latencies) * 1000 if latencies else 0.0
    summary = {
        "observations_requested": args.observations,
        "observations_processed": processed,
        "elapsed_seconds": round(elapsed, 4),
        "observations_per_second": round(rate, 1),
        "enqueue_latency_p50_ms": round(statistics.median(latencies) * 1000, 4)
        if latencies
        else 0.0,
        "enqueue_latency_p99_ms": round(p99, 4),
        "episodes_started": view["totals"]["episodes_started"],
        "app_queue_drops": view["operational"]["app_queue_drops_total"],
        "rules": len(config.rules),
        "note": (
            "Cross-platform pure pipeline microbench. "
            "Not a substitute for the Linux AF_PACKET 10k/s gate."
        ),
    }
    print(json.dumps(summary, indent=2))
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.write}", file=sys.stderr)
    return 0 if processed >= args.observations * 0.99 else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import logging
import platform
import signal
import sys
import threading
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

from .config import (
    ConfigError,
    detect_config_version,
    load_config,
    load_v2_config,
    validate_v2_config,
)
from .enforcement import render_nftables
from .engine import PolicyEngine
from .migration import MigrationRequest, migrate_v1_policy
from .models import FieldPresence, Observation, PacketMetadata
from .monitor import LiveMonitor
from .policy import compile_policy, evaluate_policy
from .replay import replay_pcap


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ibn-monitor",
        description="Continuously monitor network traffic against intent-based policies.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run live AF_PACKET capture (Linux, policy v2)")
    run_parser.add_argument("--config", default="config/policy.v2.example.json")
    run_parser.add_argument("--interface", help="Override single capture-point interface")
    run_parser.add_argument(
        "--pcap",
        help="Removed: use ibn-monitor replay instead",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate a policy file")
    validate_parser.add_argument("--config", default="config/policy.json")
    validate_parser.add_argument(
        "--format", choices=["human", "json"], default="json"
    )
    validate_parser.add_argument("--strict", action="store_true")

    check_parser = subparsers.add_parser("check", help="Evaluate one synthetic flow")
    check_parser.add_argument("--config", default="config/policy.json")
    check_parser.add_argument("--source", required=True)
    check_parser.add_argument("--destination", required=True)
    check_parser.add_argument("--protocol", choices=["tcp", "udp", "icmp"], required=True)
    check_parser.add_argument("--source-port", type=int)
    check_parser.add_argument("--destination-port", type=int)
    check_parser.add_argument(
        "--format", choices=["human", "json"], default="json"
    )

    nft_parser = subparsers.add_parser(
        "render-nftables", help="Render action=drop rules as an nftables ruleset"
    )
    nft_parser.add_argument("--config", default="config/policy.json")
    nft_parser.add_argument("--output")

    migrate_parser = subparsers.add_parser(
        "migrate-policy", help="Convert an explicit v1 policy to a v2 candidate"
    )
    migrate_parser.add_argument("--config", required=True)
    migrate_parser.add_argument("--output", required=True)
    migrate_parser.add_argument("--sensor-id", required=True)
    migrate_parser.add_argument(
        "--topology", choices=["gateway", "mirror", "host"], required=True
    )
    migrate_parser.add_argument(
        "--capture-point",
        required=True,
        metavar="NAME=INTERFACE",
    )

    replay_parser = subparsers.add_parser(
        "replay", help="Evaluate classic PCAP using v2 event-time semantics"
    )
    replay_parser.add_argument("--config", required=True)
    replay_parser.add_argument("--pcap", required=True)
    replay_parser.add_argument("--output", required=True)
    replay_parser.add_argument("--summary-output", default="-")
    replay_parser.add_argument("--boot-id")

    return parser


def _synthetic_observation(args: argparse.Namespace, sensor_id: str) -> Observation:
    source = ip_address(args.source)
    destination = ip_address(args.destination)
    if source.version != destination.version:
        raise ConfigError("source and destination IP versions must match")
    fields = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
        | FieldPresence.PROTOCOL
    )
    if args.source_port is not None:
        fields |= FieldPresence.SOURCE_PORT
    if args.destination_port is not None:
        fields |= FieldPresence.DESTINATION_PORT
    return Observation(
        captured_at=datetime.now(UTC),
        monotonic_at=None,
        sensor_id=sensor_id,
        source_generation="synthetic-check",
        capture_point="synthetic",
        interface=None,
        direction="unknown",
        wire_length=0,
        ip_version=source.version,
        source=source,
        destination=destination,
        protocol=args.protocol.lower(),
        source_port=args.source_port,
        destination_port=args.destination_port,
        fields=fields,
        outcome="complete",
    )


def _print_diagnostics(diagnostics, *, fmt: str) -> None:
    if fmt == "json":
        return
    for item in diagnostics:
        print(f"{item.severity}: {item.code} {item.path}: {item.message}", file=sys.stderr)


def _validate(args: argparse.Namespace) -> int:
    version = detect_config_version(args.config)
    if version == 1:
        config = load_config(args.config)
        payload = {
            "valid": True,
            "version": config.version,
            "enabled_rules": sum(rule.enabled for rule in config.rules),
            "drop_rules": sum(
                rule.enabled and rule.action == "drop" for rule in config.rules
            ),
        }
        print(json.dumps(payload, indent=2))
        return 0
    if version != 2:
        raise ConfigError(f"unsupported config version: {version}")

    result = validate_v2_config(args.config)
    diagnostics = [item.to_dict() for item in result.diagnostics]
    payload: dict[str, object] = {
        "valid": result.valid and not (
            args.strict and any(item.severity == "warning" for item in result.diagnostics)
        ),
        "version": 2,
        "diagnostics": diagnostics,
    }
    if result.config is not None:
        payload["policy_revision"] = result.config.policy_revision
        payload["config_revision"] = result.config.config_revision
        payload["enabled_rules"] = sum(rule.enabled for rule in result.config.rules)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        _print_diagnostics(result.diagnostics, fmt="human")
        if result.config is not None:
            print(
                f"valid={payload['valid']} policy_revision={result.config.policy_revision}"
            )
    has_errors = any(item.severity == "error" for item in result.diagnostics)
    has_warnings = any(item.severity == "warning" for item in result.diagnostics)
    if has_errors or (args.strict and has_warnings) or result.config is None:
        return 2
    return 0


def _check(args: argparse.Namespace) -> int:
    version = detect_config_version(args.config)
    if version == 1:
        config = load_config(args.config)
        try:
            ip_address(args.source)
            ip_address(args.destination)
        except ValueError as exc:
            raise ConfigError(f"Invalid IP address: {exc}") from exc
        packet = PacketMetadata(
            timestamp="synthetic",
            interface=None,
            source=args.source,
            destination=args.destination,
            protocol=args.protocol,
            source_port=args.source_port,
            destination_port=args.destination_port,
        )
        matches = PolicyEngine(config.rules).evaluate(packet)
        print(
            json.dumps(
                {
                    "matched": bool(matches),
                    "rules": [
                        {
                            "id": rule.id,
                            "severity": rule.severity,
                            "action": rule.action,
                        }
                        for rule in matches
                    ],
                },
                indent=2,
            )
        )
        return 2 if matches else 0

    if version != 2:
        raise ConfigError(f"unsupported config version: {version}")

    config = load_v2_config(args.config)
    try:
        observation = _synthetic_observation(args, config.sensor.id)
    except ValueError as exc:
        raise ConfigError(f"Invalid IP address: {exc}") from exc
    matches = evaluate_policy(
        compile_policy(config.rules, config.policy_revision), observation
    )
    payload = {
        "matched": bool(matches),
        "rules": [
            {
                "id": match.rule.id,
                "severity": match.rule.severity,
                "enforcement": match.rule.enforcement,
            }
            for match in matches
        ],
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        if not matches:
            print("no matches")
        for match in matches:
            print(
                f"{match.rule.id} severity={match.rule.severity} "
                f"enforcement={match.rule.enforcement}"
            )
    return 1 if matches else 0


def _migrate(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists():
        raise ConfigError(f"refusing to overwrite existing output: {output}")
    if "=" not in args.capture_point:
        raise ConfigError("--capture-point must be NAME=INTERFACE")
    name, interface = args.capture_point.split("=", 1)
    if not name or not interface:
        raise ConfigError("--capture-point must be NAME=INTERFACE with non-empty halves")

    raw = json.loads(Path(args.config).read_text(encoding="utf-8"))
    result = migrate_v1_policy(
        raw,
        MigrationRequest(
            sensor_id=args.sensor_id,
            topology=args.topology,
            capture_point_name=name,
            interface=interface,
        ),
    )
    if not result.valid or result.payload is None:
        for item in result.diagnostics:
            print(f"{item.code} {item.path}: {item.message}", file=sys.stderr)
        return 2

    # Validate candidate before writing.
    candidate = output.with_suffix(output.suffix + ".tmp")
    candidate.write_text(
        json.dumps(result.payload, indent=2) + "\n", encoding="utf-8"
    )
    try:
        load_v2_config(candidate)
    except ConfigError:
        candidate.unlink(missing_ok=True)
        raise
    candidate.replace(output)
    print(output)
    return 0


def _replay(args: argparse.Namespace) -> int:
    version = detect_config_version(args.config)
    if version != 2:
        raise ConfigError("replay requires a version 2 policy")
    config = load_v2_config(args.config)
    events_path = Path(args.output)
    summary_path = None if args.summary_output == "-" else Path(args.summary_output)
    if summary_path is not None and events_path.resolve() == summary_path.resolve():
        raise ConfigError("event and summary output paths must differ")
    if events_path.exists():
        raise ConfigError(f"refusing to overwrite existing output: {events_path}")
    if summary_path is not None and summary_path.exists():
        raise ConfigError(f"refusing to overwrite existing summary: {summary_path}")

    boot_id = args.boot_id or str(uuid.uuid4())
    events_path.parent.mkdir(parents=True, exist_ok=True)
    with events_path.open("w", encoding="utf-8") as stream:
        summary = replay_pcap(config, args.pcap, stream, boot_id=boot_id)
    summary_json = json.dumps(summary.to_dict(), indent=2) + "\n"
    if summary_path is None:
        print(summary_json, end="")
    else:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(summary_json, encoding="utf-8")
    return 0


def _run(args: argparse.Namespace) -> int:
    if args.pcap:
        raise ConfigError(
            "run --pcap was removed with Scapy; use: ibn-monitor replay "
            "--config <v2> --pcap FILE --output EVENTS"
        )

    version = detect_config_version(args.config)
    if version != 2:
        raise ConfigError(
            f"live run requires policy version 2 (got {version}); "
            "migrate with migrate-policy or use config/policy.v2.example.json"
        )
    if platform.system().lower() != "linux":
        raise ConfigError("live run requires Linux AF_PACKET")

    config = load_v2_config(args.config)
    if args.interface:
        if len(config.sensor.capture_points) != 1:
            raise ConfigError("--interface requires exactly one capture point")
        point = replace(config.sensor.capture_points[0], interface=args.interface)
        config = replace(config, sensor=replace(config.sensor, capture_points=(point,)))

    monitor = LiveMonitor(config, config_path=args.config)
    stop_event = threading.Event()
    force: dict[str, int | None] = {"signum": None}

    def request_stop(signum: int, frame: object) -> None:
        if stop_event.is_set():
            force["signum"] = signum
            monitor.request_shutdown(force=True)
        else:
            stop_event.set()
            monitor.request_shutdown(force=False)

    def request_reload(signum: int, frame: object) -> None:
        monitor.request_reload()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, request_reload)

    try:
        monitor.start()
        while not stop_event.wait(0.5):
            pass
    finally:
        monitor.stop(force=force["signum"] is not None)
    if force["signum"] == signal.SIGINT:
        return 130
    if force["signum"] == getattr(signal, "SIGTERM", None):
        return 143
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = build_parser().parse_args(argv)

    try:
        if args.command == "validate":
            return _validate(args)

        if args.command == "check":
            return _check(args)

        if args.command == "migrate-policy":
            return _migrate(args)

        if args.command == "replay":
            return _replay(args)

        if args.command == "render-nftables":
            config = load_config(args.config)
            rendered = render_nftables(config)
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered, encoding="utf-8")
                print(output)
            else:
                print(rendered, end="")
            return 0

        if args.command == "run":
            return _run(args)

    except ConfigError as exc:
        logging.error("Configuration error: %s", exc)
        return 2
    except PermissionError:
        logging.error("Packet capture requires CAP_NET_RAW or root privileges")
        return 3
    except OSError as exc:
        logging.error("Runtime error: %s", exc)
        return 4

    return 1


if __name__ == "__main__":
    sys.exit(main())

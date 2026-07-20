from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path

from .capture import PcapReplaySource, ScapyLiveSource
from .config import ConfigError, load_config
from .enforcement import render_nftables
from .engine import PolicyEngine
from .models import PacketMetadata
from .monitor import MonitorService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ibn-monitor",
        description="Continuously monitor network traffic against intent-based policies.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run live capture or process a PCAP file")
    run_parser.add_argument("--config", default="config/policy.json")
    run_parser.add_argument("--interface", help="Override sensor.interface")
    run_parser.add_argument("--pcap", help="Read a PCAP file instead of live traffic")

    validate_parser = subparsers.add_parser("validate", help="Validate a policy file")
    validate_parser.add_argument("--config", default="config/policy.json")

    check_parser = subparsers.add_parser("check", help="Evaluate one synthetic flow")
    check_parser.add_argument("--config", default="config/policy.json")
    check_parser.add_argument("--source", required=True)
    check_parser.add_argument("--destination", required=True)
    check_parser.add_argument("--protocol", choices=["tcp", "udp", "icmp"], required=True)
    check_parser.add_argument("--source-port", type=int)
    check_parser.add_argument("--destination-port", type=int)

    nft_parser = subparsers.add_parser(
        "render-nftables", help="Render action=drop rules as an nftables ruleset"
    )
    nft_parser.add_argument("--config", default="config/policy.json")
    nft_parser.add_argument("--output")

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = build_parser().parse_args(argv)

    try:
        if args.command == "validate":
            config = load_config(args.config)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "version": config.version,
                        "enabled_rules": sum(rule.enabled for rule in config.rules),
                        "drop_rules": sum(
                            rule.enabled and rule.action == "drop" for rule in config.rules
                        ),
                    },
                    indent=2,
                )
            )
            return 0

        if args.command == "check":
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
            config = load_config(args.config)
            if args.interface:
                config = replace(config, sensor=replace(config.sensor, interface=args.interface))
            if args.pcap:
                service = MonitorService(config, PcapReplaySource(args.pcap))
                try:
                    service.start()  # blocks until the PCAP is exhausted
                finally:
                    service.stop()
                return 0

            service = MonitorService(config, ScapyLiveSource(config.sensor))
            stop_event = threading.Event()
            reload_event = threading.Event()

            def request_stop(signum: int, frame: object) -> None:
                stop_event.set()

            def request_reload(signum: int, frame: object) -> None:
                reload_event.set()

            signal.signal(signal.SIGINT, request_stop)
            signal.signal(signal.SIGTERM, request_stop)
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, request_reload)

            try:
                service.start()
                while not stop_event.wait(0.5):
                    if reload_event.is_set():
                        reload_event.clear()
                        try:
                            reloaded = load_config(args.config)
                        except ConfigError as exc:
                            logging.error("Policy reload failed; keeping existing rules: %s", exc)
                        else:
                            service.reload_rules(reloaded.rules)
            finally:
                service.stop()
            return 0

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

from __future__ import annotations

import re
from itertools import product

from .config import AppConfig
from .models import Rule


def render_nftables(config: AppConfig) -> str:
    lines = [
        "#!/usr/sbin/nft -f",
        "",
        "add table inet ibn_monitor",
        "flush table inet ibn_monitor",
        "add chain inet ibn_monitor forward { type filter hook forward priority filter; policy accept; }",
        "",
    ]

    rendered = 0
    for rule in config.rules:
        if not rule.enabled or rule.action != "drop":
            continue
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", rule.id)[:32]
        comment = f"{rule.id}: {rule.description}".replace("\r", " ").replace("\n", " ")
        for expression in _rule_expressions(rule):
            lines.append(f"# {comment}")
            lines.append(
                f'add rule inet ibn_monitor forward {expression} limit rate 10/second log prefix "IBN {safe_id} "'
            )
            lines.append(f"add rule inet ibn_monitor forward {expression} counter drop")
            rendered += 1

    if rendered == 0:
        lines.append("# No enabled rules with action=drop were configured.")
    lines.append("")
    return "\n".join(lines)


def _rule_expressions(rule: Rule) -> list[str]:
    source_versions = {network.version for network in rule.source_cidrs} or {4, 6}
    destination_versions = {network.version for network in rule.destination_cidrs} or {4, 6}
    versions = sorted(source_versions & destination_versions)
    expressions: list[str] = []

    for version in versions:
        family = "ip" if version == 4 else "ip6"
        sources = [network for network in rule.source_cidrs if network.version == version] or [None]
        destinations = [
            network for network in rule.destination_cidrs if network.version == version
        ] or [None]
        ports = sorted(rule.destination_ports)
        # Anonymous set keeps multi-port rules as a single nft rule instead of a
        # per-port cartesian expansion.
        port_match = None
        if len(ports) == 1:
            port_match = str(ports[0])
        elif ports:
            port_match = "{ " + ", ".join(str(port) for port in ports) + " }"

        for source, destination in product(sources, destinations):
            parts: list[str] = []
            if source is not None:
                parts.extend([family, "saddr", str(source)])
            if destination is not None:
                parts.extend([family, "daddr", str(destination)])
            if port_match is not None:
                parts.extend([rule.protocol, "dport", port_match])
            elif rule.protocol != "any":
                protocol = "icmpv6" if rule.protocol == "icmp" and version == 6 else rule.protocol
                parts.extend(["meta", "l4proto", protocol])
            expressions.append(" ".join(parts))

    return expressions

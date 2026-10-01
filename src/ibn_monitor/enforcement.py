"""Deterministic topology-aware nftables rendering for v2 policies."""

from __future__ import annotations

import re
from itertools import product

from .config import ConfigError, PolicyV2Config
from .models import PolicyRule


def render_nftables_v2(config: PolicyV2Config) -> str:
    """Topology-aware v2 renderer for nftables_drop_candidate rules.

    - gateway → forward chain
    - host → input + output chains (identical predicates)
    - mirror → ConfigError (cannot enforce on a mirror sensor)
    """
    topology = config.sensor.topology
    if topology == "mirror":
        raise ConfigError(
            "mirror topology cannot render nftables enforcement; "
            "detection-only sensors must keep enforcement=none or change topology"
        )

    chains = _chains_for_topology(topology)
    candidates = tuple(
        rule
        for rule in sorted(config.rules, key=lambda item: item.id)
        if rule.enabled and rule.enforcement == "nftables_drop_candidate"
    )

    lines = [
        "#!/usr/sbin/nft -f",
        "",
        f"# ibn-monitor v2 topology={topology}",
        f"# policy_revision={config.policy_revision}",
        f"# config_revision={config.config_revision}",
        f"# sensor_id={config.sensor.id}",
        "",
        # ``destroy`` is idempotent when the table is absent, unlike ``delete``.
        # Recreate the managed table so stale chains cannot make a reapply fail.
        "destroy table inet ibn_monitor",
        "add table inet ibn_monitor",
    ]
    for chain, hook in chains:
        lines.append(
            f"add chain inet ibn_monitor {chain} "
            f"{{ type filter hook {hook} priority filter; policy accept; }}"
        )
    lines.append("")

    rendered = 0
    for rule in candidates:
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", rule.id)[:32]
        comment = f"{rule.id}: {rule.description}".replace("\r", " ").replace("\n", " ")
        for expression in _v2_rule_expressions(rule):
            for chain, _hook in chains:
                lines.append(f"# {comment}")
                lines.append(
                    f"add rule inet ibn_monitor {chain} {expression} "
                    f'limit rate 10/second log prefix "IBN {safe_id} "'
                )
                lines.append(f"add rule inet ibn_monitor {chain} {expression} counter drop")
                rendered += 1

    if rendered == 0:
        lines.append("# No enabled rules with enforcement=nftables_drop_candidate were configured.")
    lines.append("")
    return "\n".join(lines)


def _chains_for_topology(topology: str) -> tuple[tuple[str, str], ...]:
    if topology == "gateway":
        return (("forward", "forward"),)
    if topology == "host":
        return (("input", "input"), ("output", "output"))
    raise ConfigError(f"unsupported topology for nftables: {topology}")


def _v2_rule_expressions(rule: PolicyRule) -> list[str]:
    match = rule.match
    source_versions = {network.version for network in match.source_cidrs}
    destination_versions = {network.version for network in match.destination_cidrs}
    versions = sorted(source_versions & destination_versions)
    if not versions:
        raise ConfigError(
            f"rule {rule.id} has no overlapping IP family between source and destination CIDRs"
        )

    expressions: list[str] = []
    for version in versions:
        family = "ip" if version == 4 else "ip6"
        sources = sorted(
            (n for n in match.source_cidrs if n.version == version),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        destinations = sorted(
            (n for n in match.destination_cidrs if n.version == version),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        ports = None if match.destination_ports is None else sorted(match.destination_ports)
        port_match = None
        if ports is not None:
            if len(ports) == 1:
                port_match = str(ports[0])
            elif ports:
                port_match = "{ " + ", ".join(str(port) for port in ports) + " }"

        for source, destination in product(sources, destinations):
            parts: list[str] = [family, "saddr", str(source), family, "daddr", str(destination)]
            protocol = match.protocol
            if port_match is not None:
                if protocol not in {"tcp", "udp"}:
                    raise ConfigError(
                        f"rule {rule.id} has destination ports but protocol={protocol}"
                    )
                parts.extend([protocol, "dport", port_match])
            elif protocol == "any":
                pass
            elif protocol == "icmp":
                l4 = "icmpv6" if version == 6 else "icmp"
                parts.extend(["meta", "l4proto", l4])
            else:
                parts.extend(["meta", "l4proto", protocol])
            expressions.append(" ".join(parts))

    # Stable order for byte-identical re-renders
    return sorted(set(expressions))

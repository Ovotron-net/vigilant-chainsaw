from __future__ import annotations

from dataclasses import dataclass

from .models import FieldPresence, Network, Observation, PolicyRule


@dataclass(frozen=True, slots=True)
class CompiledPredicate:
    rule: PolicyRule
    ip_version: int
    source_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    revision: str
    predicates: tuple[CompiledPredicate, ...]


@dataclass(frozen=True, slots=True)
class PolicyMatchResult:
    rule: PolicyRule
    predicate: CompiledPredicate


def compile_policy(rules: tuple[PolicyRule, ...], revision: str) -> CompiledPolicy:
    predicates: list[CompiledPredicate] = []
    for rule in sorted(rules, key=lambda item: item.id):
        if not rule.enabled:
            continue
        source_versions = {network.version for network in rule.match.source_cidrs}
        destination_versions = {
            network.version for network in rule.match.destination_cidrs
        }
        for version in sorted(source_versions & destination_versions):
            predicates.append(
                CompiledPredicate(
                    rule=rule,
                    ip_version=version,
                    source_cidrs=tuple(
                        network
                        for network in rule.match.source_cidrs
                        if network.version == version
                    ),
                    destination_cidrs=tuple(
                        network
                        for network in rule.match.destination_cidrs
                        if network.version == version
                    ),
                )
            )
    return CompiledPolicy(revision=revision, predicates=tuple(predicates))


def _required_fields(rule: PolicyRule) -> FieldPresence:
    required = FieldPresence.IP_VERSION | FieldPresence.SOURCE | FieldPresence.DESTINATION
    if rule.match.protocol != "any":
        required |= FieldPresence.PROTOCOL
    if rule.match.destination_ports is not None:
        required |= FieldPresence.DESTINATION_PORT
    return required


def evaluate_policy(
    policy: CompiledPolicy, observation: Observation
) -> tuple[PolicyMatchResult, ...]:
    if observation.source is None or observation.destination is None:
        return ()
    matches: list[PolicyMatchResult] = []
    for predicate in policy.predicates:
        rule = predicate.rule
        if observation.ip_version != predicate.ip_version:
            continue
        required = _required_fields(rule)
        if observation.fields & required != required:
            continue
        if not any(observation.source in network for network in predicate.source_cidrs):
            continue
        if not any(
            observation.destination in network for network in predicate.destination_cidrs
        ):
            continue
        if rule.match.protocol != "any" and observation.protocol != rule.match.protocol:
            continue
        ports = rule.match.destination_ports
        if ports is not None and observation.destination_port not in ports:
            continue
        matches.append(PolicyMatchResult(rule=rule, predicate=predicate))
    return tuple(matches)


def _ports_intersect(
    left: frozenset[int] | None, right: frozenset[int] | None
) -> bool:
    if left is None or right is None:
        return True
    return bool(left & right)


def _networks_overlap(left: tuple[Network, ...], right: tuple[Network, ...]) -> bool:
    for left_network in left:
        for right_network in right:
            if left_network.version != right_network.version:
                continue
            if left_network.overlaps(right_network):
                return True
    return False


def find_overlaps(rules: tuple[PolicyRule, ...]) -> tuple[tuple[str, str], ...]:
    enabled = [rule for rule in rules if rule.enabled]
    pairs: list[tuple[str, str]] = []
    for index, left in enumerate(enabled):
        for right in enabled[index + 1 :]:
            if not _networks_overlap(left.match.source_cidrs, right.match.source_cidrs):
                continue
            if not _networks_overlap(
                left.match.destination_cidrs, right.match.destination_cidrs
            ):
                continue
            protocols_ok = (
                left.match.protocol == right.match.protocol
                or left.match.protocol == "any"
                or right.match.protocol == "any"
            )
            if not protocols_ok:
                continue
            if not _ports_intersect(
                left.match.destination_ports, right.match.destination_ports
            ):
                continue
            pair = tuple(sorted((left.id, right.id)))
            pairs.append((pair[0], pair[1]))
    return tuple(sorted(set(pairs)))

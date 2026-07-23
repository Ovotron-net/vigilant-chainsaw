from dataclasses import replace
from ipaddress import ip_network

from factories import observation, policy_rule

from ibn_monitor.models import FieldPresence, PolicyMatch
from ibn_monitor.policy import compile_policy, evaluate_policy, find_overlaps


def test_reports_every_matching_rule():
    rules = (policy_rule(id="R1"), policy_rule(id="R2", enforcement="none"))
    matches = evaluate_policy(compile_policy(rules, "a" * 64), observation())
    assert [match.rule.id for match in matches] == ["R1", "R2"]


def test_partial_observation_matches_only_when_constrained_fields_are_known():
    cidr_only = policy_rule(
        id="CIDR",
        match=PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.0.0/16"),),
            protocol="any",
            destination_ports=None,
        ),
    )
    partial = replace(
        observation(),
        protocol=None,
        source_port=None,
        destination_port=None,
        fields=(
            FieldPresence.IP_VERSION | FieldPresence.SOURCE | FieldPresence.DESTINATION
        ),
        outcome="partial",
        decode_reason="ipv6_extension_limit",
    )
    assert [
        item.rule.id
        for item in evaluate_policy(
            compile_policy((cidr_only, policy_rule()), "b" * 64), partial
        )
    ] == ["CIDR"]


def test_overlap_detection_is_stable_and_ignores_disabled_rules():
    rules = (
        policy_rule(id="BROAD"),
        policy_rule(id="NARROW"),
        policy_rule(id="OFF", enabled=False),
    )
    assert find_overlaps(rules) == (("BROAD", "NARROW"),)

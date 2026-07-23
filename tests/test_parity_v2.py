"""Detector / renderer parity: matching rules that render must be expressible."""

from __future__ import annotations

from ipaddress import ip_network

from factories import observation, policy_rule, v2_config

from ibn_monitor.enforcement import render_nftables_v2
from ibn_monitor.models import PolicyMatch
from ibn_monitor.policy import compile_policy, evaluate_policy


def test_matching_drop_candidate_appears_in_nft_artifact():
    rule = policy_rule(
        id="PARITY",
        enforcement="nftables_drop_candidate",
        match=PolicyMatch(
            source_cidrs=(ip_network("10.20.0.0/16"),),
            destination_cidrs=(ip_network("10.50.10.8/32"),),
            protocol="tcp",
            destination_ports=frozenset({5432}),
        ),
    )
    config = v2_config(rules=(rule,))
    matches = evaluate_policy(
        compile_policy(config.rules, config.policy_revision), observation()
    )
    assert [m.rule.id for m in matches] == ["PARITY"]
    artifact = render_nftables_v2(config)
    assert "tcp dport 5432" in artifact
    assert "10.20.0.0/16" in artifact
    assert "10.50.10.8" in artifact
    assert "counter drop" in artifact


def test_enforcement_none_matches_but_does_not_render():
    rule = policy_rule(id="ALERT", enforcement="none")
    config = v2_config(rules=(rule,))
    matches = evaluate_policy(
        compile_policy(config.rules, config.policy_revision), observation()
    )
    assert matches
    artifact = render_nftables_v2(config)
    assert "ALERT" not in artifact
    assert "counter drop" not in artifact

from ipaddress import ip_network

import pytest
from factories import policy_rule, v2_config

from ibn_monitor.config import ConfigError
from ibn_monitor.enforcement import render_nftables_v2
from ibn_monitor.models import PolicyMatch


def test_gateway_renders_forward_only():
    config = v2_config()
    output = render_nftables_v2(config)
    assert "topology=gateway" in output
    assert f"policy_revision={config.policy_revision}" in output
    assert "add chain inet ibn_monitor forward" in output
    assert "add chain inet ibn_monitor input" not in output
    assert "ip saddr 10.20.0.0/16 ip daddr 10.50.10.8/32 tcp dport 5432" in output
    assert "counter drop" in output
    # Deterministic re-render
    assert output == render_nftables_v2(config)


def test_host_renders_input_and_output():
    base = v2_config()
    from dataclasses import replace

    sensor = replace(base.sensor, topology="host")
    config = replace(base, sensor=sensor)
    # recompute config revision after topology change for realistic wire
    from ibn_monitor.config import canonical_config_revision

    config = replace(config, config_revision=canonical_config_revision(config))
    output = render_nftables_v2(config)
    assert "topology=host" in output
    assert "add chain inet ibn_monitor input" in output
    assert "add chain inet ibn_monitor output" in output
    assert output.count("counter drop") == 2  # one per chain for single expression


def test_mirror_rejects_render():
    base = v2_config()
    from dataclasses import replace

    sensor = replace(base.sensor, topology="mirror")
    config = replace(base, sensor=sensor)
    with pytest.raises(ConfigError, match="mirror topology"):
        render_nftables_v2(config)


def test_skips_enforcement_none():
    config = v2_config(rules=(policy_rule(enforcement="none"),))
    output = render_nftables_v2(config)
    assert "No enabled rules with enforcement=nftables_drop_candidate" in output
    assert "counter drop" not in output


def test_multi_port_anonymous_set_sorted():
    config = v2_config(
        rules=(
            policy_rule(
                match=PolicyMatch(
                    source_cidrs=(ip_network("10.0.0.0/8"),),
                    destination_cidrs=(ip_network("192.0.2.1/32"),),
                    protocol="tcp",
                    destination_ports=frozenset({5432, 3306}),
                )
            ),
        )
    )
    output = render_nftables_v2(config)
    assert "tcp dport { 3306, 5432 }" in output

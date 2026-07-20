from factories import metadata, rule

from ibn_monitor.engine import PolicyEngine


def test_policy_matches_prohibited_flow():
    packet = metadata()
    assert PolicyEngine((rule(),)).evaluate(packet)[0].id == "DEV-DB"


def test_policy_ignores_allowed_port():
    packet = metadata(destination_port=443)
    assert PolicyEngine((rule(),)).evaluate(packet) == []

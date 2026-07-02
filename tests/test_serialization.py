"""Tests for YAML / Rego import-export and to_dict round-tripping."""
from sentinel_policy import Policy, from_yaml, to_rego, to_yaml


def _policy():
    return Policy.from_dict({
        "version": 2, "name": "prod-controls", "default": "deny",
        "rules": [
            {"id": "reads", "effect": "allow", "doctrine": "S2",
             "match": {"action": "read.*"}},
            {"id": "gate", "effect": "require_approval", "tier": "high",
             "doctrine": "S3", "priority": 10,
             "match": {"action": "deploy", "params.env": {"eq": "prod"}},
             "reason": "prod deploys are gated"},
            {"id": "block-cidr", "effect": "deny", "doctrine": "S6",
             "match": {"src.ip": {"cidr": "10.0.0.0/8"}}},
        ],
    })


def test_to_dict_roundtrip():
    p = _policy()
    p2 = Policy.from_dict(p.to_dict())
    assert p.to_dict() == p2.to_dict()


def test_yaml_roundtrip_preserves_semantics():
    p = _policy()
    text = to_yaml(p)
    assert isinstance(text, str) and text.strip()
    p2 = from_yaml(text)
    assert p.to_dict() == p2.to_dict()


def test_yaml_roundtrip_evaluates_the_same():
    p = _policy()
    p2 = from_yaml(to_yaml(p))
    for d in ({"action": "read.logs"},
              {"action": "deploy", "params": {"env": "prod"}},
              {"action": "x", "src": {"ip": "10.1.1.1"}}):
        assert p.evaluate(d).effect is p2.evaluate(d).effect


def test_yaml_handles_bool_and_int_and_nested():
    p = Policy.from_dict({
        "name": "t", "default": "deny", "version": 1,
        "rules": [{"id": "r", "effect": "require_approval", "tier": "high",
                   "match": {"params.irreversible": {"eq": True},
                             "params.n": {"gt": 3}}}],
    })
    p2 = from_yaml(to_yaml(p))
    assert p2.rules[0].match["params.irreversible"]["eq"] is True
    assert p2.rules[0].match["params.n"]["gt"] == 3


def test_rego_export_is_readable_and_cites_doctrine():
    rego = to_rego(_policy())
    assert "package sentinel" in rego
    assert 'default decision := "deny"' in rego
    assert 'decision := "allow"' in rego
    assert "doctrine S2" in rego
    assert "net.cidr_contains" in rego          # cidr op mapped
    assert "input.action" in rego
    # every rule id appears as a trailing comment
    for rid in ("reads", "gate", "block-cidr"):
        assert rid in rego


def test_rego_custom_package_name():
    assert "package myorg" in to_rego(_policy(), package="myorg")

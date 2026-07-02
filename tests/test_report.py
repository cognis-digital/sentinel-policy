"""Tests for the combined lint + coverage + shape report."""
from sentinel_policy import Policy, build_report


def test_report_on_valid_policy():
    p = Policy.from_dict({
        "name": "t", "default": "deny",
        "rules": [
            {"id": "a", "effect": "allow", "doctrine": "S2", "match": {"action": "read.*"}},
            {"id": "b", "effect": "require_approval", "tier": "high",
             "doctrine": "S3", "match": {"params.env": {"eq": "prod"}}},
        ],
    })
    rep = build_report(p)
    assert rep.valid
    assert rep.rule_count == 2
    assert rep.covered == ["S2", "S3"]
    assert set(rep.uncovered) == {"S1", "S4", "S5", "S6", "S7"}
    assert rep.effect_mix == {"allow": 1, "require_approval": 1}
    assert rep.operators_used.get("eq") == 1
    assert 0 < rep.coverage_pct < 100
    assert not rep.dead_rules


def test_report_flags_invalid_policy():
    p = Policy.from_dict({
        "name": "t", "default": "deny",
        "rules": [
            {"id": "dup", "effect": "allow", "match": {}},
            {"id": "dup", "effect": "deny", "match": {}},   # duplicate id
            {"id": "bad", "effect": "require_approval", "match": {}},  # no tier
        ],
    })
    rep = build_report(p)
    assert not rep.valid
    assert any("duplicate" in x for x in rep.problems)
    assert any("no tier" in x for x in rep.problems)


def test_dead_rule_detection():
    p = Policy.from_dict({
        "name": "t", "default": "deny",
        "rules": [
            {"id": "catch-all", "effect": "allow", "match": {}},   # matches everything
            {"id": "never", "effect": "deny", "match": {"action": "x"}},
        ],
    })
    rep = build_report(p)
    assert rep.dead_rules == ["never"]
    assert "DEAD RULES" in rep.render()


def test_report_render_contains_key_sections():
    p = Policy.from_dict({"name": "t", "default": "deny",
                          "rules": [{"id": "a", "effect": "allow",
                                     "doctrine": "S2", "match": {"action": "x"}}]})
    text = build_report(p).render()
    for token in ("policy", "valid", "coverage", "effects"):
        assert token in text


def test_report_as_dict_serializable():
    p = Policy.from_dict({"name": "t", "default": "deny",
                          "rules": [{"id": "a", "effect": "allow",
                                     "doctrine": "S2", "match": {"action": "x"}}]})
    d = build_report(p).as_dict()
    assert d["valid"] is True
    assert d["coverage_pct"] > 0

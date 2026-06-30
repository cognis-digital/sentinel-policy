"""Tests for ``Policy.validate()`` — the lint surface.

``validate`` returns a list of human-readable problems (empty == valid) rather
than raising, because a linter wants to report *all* problems at once. These
cover each problem category plus the clean case.
"""
from pathlib import Path

from sentinel_policy import Effect, Policy, load_policy

EXAMPLE = Path(__file__).resolve().parent.parent / "policies" / "example.json"


def test_shipped_policy_is_clean():
    assert load_policy(str(EXAMPLE)).validate() == []


def test_clean_code_built_policy():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "doctrine": "S2", "effect": "allow",
                   "match": {"action": "read.*"}}],
    })
    assert policy.validate() == []


def test_duplicate_ids_flagged_once_per_dup():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [
            {"id": "dup", "effect": "allow", "match": {"a": "1"}},
            {"id": "dup", "effect": "deny", "match": {"a": "2"}},
        ],
    })
    probs = policy.validate()
    assert sum("duplicate" in p for p in probs) == 1


def test_unknown_doctrine_flagged():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "doctrine": "S99", "effect": "allow",
                   "match": {"a": "1"}}],
    })
    assert any("S99" in p and "doctrine" in p for p in policy.validate())


def test_no_doctrine_is_allowed():
    # doctrine is optional; a rule without one is not a validate problem
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "allow", "match": {"a": "1"}}],
    })
    assert policy.validate() == []


def test_unknown_operator_flagged():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "deny",
                   "match": {"a": {"approx": 1}}}],
    })
    assert any("approx" in p for p in policy.validate())


def test_each_known_operator_passes_validate():
    for op, operand in [("eq", 1), ("ne", 1), ("in", [1, 2]), ("nin", [1]),
                        ("glob", "a*"), ("contains", "x"), ("exists", True),
                        ("gt", 1), ("ge", 1), ("lt", 1), ("le", 1)]:
        policy = Policy.from_dict({
            "name": "p", "default": "deny",
            "rules": [{"id": "r", "effect": "deny", "match": {"f": {op: operand}}}],
        })
        assert policy.validate() == [], f"operator {op} should validate clean"


def test_in_with_non_list_operand_flagged():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "deny",
                   "match": {"a": {"in": 5}}}],
    })
    probs = policy.validate()
    assert any("in" in p and "list" in p for p in probs)


def test_nin_with_non_list_operand_flagged():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "deny",
                   "match": {"a": {"nin": 5}}}],
    })
    assert any("nin" in p for p in policy.validate())


def test_in_with_string_operand_is_ok():
    # a string is a valid `in` operand (substring containment)
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "deny",
                   "match": {"a": {"in": "abcdef"}}}],
    })
    assert policy.validate() == []


def test_require_approval_without_tier_flagged():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "require_approval",
                   "match": {"a": "1"}}],
    })
    assert any("tier" in p for p in policy.validate())


def test_require_approval_with_tier_is_clean():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [{"id": "r1", "effect": "require_approval", "tier": "high",
                   "match": {"a": "1"}}],
    })
    assert policy.validate() == []


def test_validate_reports_multiple_problems_at_once():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [
            {"id": "x", "doctrine": "S99", "effect": "deny",
             "match": {"a": {"bogus": 1}}},
            {"id": "x", "effect": "require_approval", "match": {"b": {"in": 7}}},
        ],
    })
    probs = policy.validate()
    # unknown doctrine + unknown op + duplicate id + missing tier + bad `in`
    assert len(probs) >= 4


def test_match_not_object_on_code_built_rule_flagged():
    # construct a rule with a non-dict match directly (bypassing from_dict)
    from sentinel_policy.policy import PolicyRule
    policy = Policy("p", [PolicyRule(id="r1", effect=Effect.ALLOW, match="oops")])
    assert any("match must be an object" in p for p in policy.validate())

"""Tests for the enriched validate() checks (kept backward-compatible)."""
from sentinel_policy import Policy


def V(rules):
    return Policy.from_dict({"name": "t", "default": "deny", "rules": rules}).validate()


def test_valid_policy_has_no_problems():
    assert V([{"id": "a", "effect": "allow", "doctrine": "S2",
               "match": {"action": "read.*"}}]) == []


def test_require_approval_without_tier_flagged():
    problems = V([{"id": "a", "effect": "require_approval", "match": {"action": "x"}}])
    assert any("no tier" in p for p in problems)


def test_collection_op_needs_list():
    problems = V([{"id": "a", "effect": "allow", "match": {"env": {"in": 5}}}])
    assert any("needs a list operand" in p for p in problems)


def test_between_needs_two_element_range():
    problems = V([{"id": "a", "effect": "allow", "match": {"n": {"between": [1]}}}])
    assert any("two-element" in p for p in problems)


def test_bad_regex_flagged():
    problems = V([{"id": "a", "effect": "allow", "match": {"s": {"regex": "("}}}])
    assert any("regex" in p for p in problems)


def test_unknown_operator_flagged():
    problems = V([{"id": "a", "effect": "allow", "match": {"s": {"nope": 1}}}])
    assert any("unknown operator" in p for p in problems)


def test_unknown_doctrine_flagged():
    problems = V([{"id": "a", "effect": "allow", "doctrine": "S9",
                   "match": {"action": "x"}}])
    assert any("unknown doctrine" in p for p in problems)


def test_duplicate_id_flagged():
    problems = V([{"id": "dup", "effect": "allow", "match": {}},
                  {"id": "dup", "effect": "deny", "match": {}}])
    assert any("duplicate" in p for p in problems)


def test_new_operators_accepted_by_validate():
    assert V([{"id": "a", "effect": "allow", "match": {
        "ip": {"cidr": "10.0.0.0/8"},
        "t": {"time_window": "09:00-17:00"},
        "s": {"regex": "^a"},
        "scopes": {"subset": ["read", "write"]},
    }}]) == []

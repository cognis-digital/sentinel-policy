"""Tests for policy diffing."""
from sentinel_policy import Policy, diff_policies


def P(rules, default="deny"):
    return Policy.from_dict({"name": "t", "default": default, "rules": rules})


def test_identical_policies_empty_diff():
    rules = [{"id": "a", "effect": "deny", "match": {"action": "x"}}]
    d = diff_policies(P(rules), P(rules))
    assert d.is_empty
    assert not d.loosens_control
    assert "identical" in d.render()


def test_added_and_removed_rules():
    old = P([{"id": "a", "effect": "deny", "match": {"action": "x"}}])
    new = P([{"id": "b", "effect": "deny", "match": {"action": "y"}}])
    d = diff_policies(old, new)
    assert [r.id for r in d.added] == ["b"]
    assert [r.id for r in d.removed] == ["a"]


def test_effect_change_detected_and_loosening_flagged():
    old = P([{"id": "a", "effect": "deny", "match": {"action": "x"}}])
    new = P([{"id": "a", "effect": "allow", "match": {"action": "x"}}])
    d = diff_policies(old, new)
    assert len(d.changed) == 1
    ch = d.changed[0]
    assert ch.rule == "a"
    assert ch.loosens
    assert d.loosens_control
    assert "WARNING" in d.render()


def test_tightening_change_not_flagged_as_loosening():
    old = P([{"id": "a", "effect": "allow", "match": {"action": "x"}}])
    new = P([{"id": "a", "effect": "deny", "match": {"action": "x"}}])
    d = diff_policies(old, new)
    assert d.changed and not d.changed[0].loosens
    assert not d.loosens_control


def test_removing_a_deny_loosens():
    old = P([{"id": "a", "effect": "deny", "match": {"action": "x"}}])
    new = P([])
    assert diff_policies(old, new).loosens_control


def test_adding_an_allow_loosens():
    old = P([])
    new = P([{"id": "a", "effect": "allow", "match": {"action": "x"}}])
    assert diff_policies(old, new).loosens_control


def test_default_change_toward_allow_loosens():
    old = P([], default="deny")
    new = P([], default="allow")
    d = diff_policies(old, new)
    assert d.default_change is not None
    assert d.loosens_control


def test_match_and_priority_changes_tracked():
    old = P([{"id": "a", "effect": "deny", "match": {"action": "x"}, "priority": 1}])
    new = P([{"id": "a", "effect": "deny", "match": {"action": "y"}, "priority": 5}])
    d = diff_policies(old, new)
    fields = {c.field for c in d.changed[0].changes}
    assert "match" in fields and "priority" in fields
    assert not d.loosens_control  # effect unchanged


def test_diff_as_dict_serializable():
    old = P([{"id": "a", "effect": "deny", "match": {"action": "x"}}])
    new = P([{"id": "a", "effect": "allow", "match": {"action": "x"}}])
    d = diff_policies(old, new).as_dict()
    assert d["loosens_control"] is True
    assert d["changed"][0]["rule"] == "a"

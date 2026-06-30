"""Error-path tests: malformed policies and files must fail with a clear
``PolicyError`` (or ``FileNotFoundError``), never a bare traceback, and the
message must name the offending rule/field so an operator can fix the JSON.
"""
import json

import pytest

from sentinel_policy import Effect, Policy, PolicyError, load_policy


def test_policy_error_is_a_value_error():
    # public API stability: existing `except ValueError` handlers keep working
    assert issubclass(PolicyError, ValueError)


def test_missing_effect_names_the_rule():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": [{"id": "r1", "match": {}}]})
    msg = str(ei.value)
    assert "r1" in msg and "effect" in msg


def test_invalid_effect_lists_valid_values():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": [
            {"id": "r1", "effect": "maybe", "match": {}}]})
    msg = str(ei.value)
    assert "maybe" in msg
    assert "allow" in msg and "deny" in msg and "require_approval" in msg


def test_invalid_default_effect():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "default": "perhaps", "rules": []})
    assert "default" in str(ei.value)


def test_rules_must_be_a_list():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": {"not": "a list"}})
    assert "rules" in str(ei.value) and "list" in str(ei.value)


def test_rule_must_be_an_object():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": ["just a string"]})
    assert "object" in str(ei.value)


def test_match_must_be_an_object():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": [
            {"id": "r1", "effect": "allow", "match": ["a", "b"]}]})
    msg = str(ei.value)
    assert "r1" in msg and "match" in msg


def test_top_level_must_be_object():
    with pytest.raises(PolicyError):
        Policy.from_dict(["not", "a", "policy"])


def test_non_integer_priority_is_caught():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "rules": [
            {"id": "r1", "effect": "allow", "match": {}, "priority": "high"}]})
    assert "priority" in str(ei.value) and "integer" in str(ei.value)


def test_non_integer_version_is_caught():
    with pytest.raises(PolicyError) as ei:
        Policy.from_dict({"name": "p", "version": "v2", "rules": []})
    assert "version" in str(ei.value)


def test_numeric_string_priority_is_accepted():
    # "5" is a valid integer; JSON numbers and numeric strings both coerce
    policy = Policy.from_dict({"name": "p", "rules": [
        {"id": "r1", "effect": "allow", "match": {"a": "b"}, "priority": "5"}]})
    assert policy.rules[0].priority == 5


def test_load_missing_file_raises_filenotfound(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(FileNotFoundError) as ei:
        load_policy(str(missing))
    assert "nope.json" in str(ei.value)


def test_load_bad_json_reports_position(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json ", encoding="utf-8")
    with pytest.raises(PolicyError) as ei:
        load_policy(str(bad))
    msg = str(ei.value)
    assert "bad.json" in msg and "line" in msg and "column" in msg


def test_load_valid_roundtrip(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({
        "name": "ok", "default": "deny",
        "rules": [{"id": "a", "effect": "allow", "match": {"action": "x"}}],
    }), encoding="utf-8")
    policy = load_policy(str(p))
    assert policy.name == "ok"
    assert policy.evaluate({"action": "x"}).allowed

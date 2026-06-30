"""Tests for Policy.doctrine_coverage() — the auditable coverage report."""
from pathlib import Path

from sentinel_policy import DOCTRINE, Policy, load_policy

EXAMPLE = Path(__file__).resolve().parent.parent / "policies" / "example.json"


def test_example_coverage_shape():
    cov = load_policy(str(EXAMPLE)).doctrine_coverage()
    assert set(cov) == {"covered", "uncovered", "by_rule", "uncited_rules"}


def test_example_covers_expected_principles():
    cov = load_policy(str(EXAMPLE)).doctrine_coverage()
    # the shipped prod-controls policy cites S2, S3, S5, S6
    assert cov["covered"] == ["S2", "S3", "S5", "S6"]


def test_covered_plus_uncovered_is_all_seven():
    cov = load_policy(str(EXAMPLE)).doctrine_coverage()
    all_ids = {d.id for d in DOCTRINE}
    assert set(cov["covered"]) | set(cov["uncovered"]) == all_ids
    assert set(cov["covered"]) & set(cov["uncovered"]) == set()


def test_uncited_rules_listed():
    p = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [
            {"id": "cited", "doctrine": "S2", "effect": "allow",
             "match": {"a": "1"}},
            {"id": "bare", "effect": "deny", "match": {"a": "2"}},
        ],
    })
    cov = p.doctrine_coverage()
    assert cov["uncited_rules"] == ["bare"]
    assert cov["covered"] == ["S2"]


def test_full_coverage_policy_has_no_gaps():
    rules = [{"id": f"r-{d.id}", "doctrine": d.id, "effect": "deny",
              "match": {"action": d.id}} for d in DOCTRINE]
    cov = Policy.from_dict({"name": "all", "rules": rules}).doctrine_coverage()
    assert cov["uncovered"] == []
    assert len(cov["covered"]) == 7


def test_empty_policy_covers_nothing():
    cov = Policy.from_dict({"name": "p", "rules": []}).doctrine_coverage()
    assert cov["covered"] == []
    assert len(cov["uncovered"]) == 7


def test_unknown_doctrine_not_counted_as_covered():
    # a rule citing a non-existent principle does not inflate coverage
    p = Policy.from_dict({
        "name": "p", "rules": [
            {"id": "r", "doctrine": "S99", "effect": "deny", "match": {"a": "1"}}],
    })
    cov = p.doctrine_coverage()
    assert "S99" not in cov["covered"]
    assert cov["covered"] == []

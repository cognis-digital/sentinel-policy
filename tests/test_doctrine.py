import pytest

from sentinel_policy import DOCTRINE, rule


def test_seven_unique_rules():
    assert len(DOCTRINE) == 7
    ids = [r.id for r in DOCTRINE]
    assert ids == ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
    assert len(set(ids)) == 7


def test_rule_lookup():
    assert rule("S6").name == "Boundary Integrity"
    assert "boundary" in rule("S6").statement.lower()


def test_unknown_rule_raises():
    with pytest.raises(KeyError):
        rule("S99")


def test_rules_have_rationale():
    assert all(r.statement and r.rationale for r in DOCTRINE)

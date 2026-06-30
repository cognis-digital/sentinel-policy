"""Extra doctrine tests: identity, immutability, lookup error paths, and the
content invariants a reviewer relies on (every rule has a statement + why).
"""
import dataclasses

import pytest

from sentinel_policy import DOCTRINE, Rule, rule


def test_rule_is_frozen():
    r = DOCTRINE[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.id = "X9"


def test_every_rule_has_all_fields_nonempty():
    for r in DOCTRINE:
        assert r.id and r.name and r.statement and r.rationale


def test_ids_are_s1_through_s7_in_order():
    assert [r.id for r in DOCTRINE] == [f"S{i}" for i in range(1, 8)]


def test_lookup_each_rule_by_id():
    for r in DOCTRINE:
        assert rule(r.id) is r


def test_lookup_unknown_raises_keyerror():
    with pytest.raises(KeyError):
        rule("S0")
    with pytest.raises(KeyError):
        rule("nonsense")


def test_rule_as_dict_roundtrip():
    r = rule("S6")
    d = r.as_dict()
    assert d["id"] == "S6"
    assert set(d) == {"id", "name", "statement", "rationale"}
    assert Rule(**d) == r


def test_names_are_unique():
    names = [r.name for r in DOCTRINE]
    assert len(set(names)) == len(names)


def test_known_doctrine_names():
    assert rule("S1").name == "Attributed Intent"
    assert rule("S7").name == "Provable Refusal"

import pytest

from sentinel_policy import conditions as C


def test_get_path_nested():
    d = {"params": {"env": "prod", "n": 3}}
    assert C.get_path(d, "params.env") == "prod"
    assert C.get_path(d, "params.missing") is None
    assert C.get_path(d, "nope.deep") is None


def test_scalar_equality_and_glob():
    assert C.matches({"action": "deploy"}, {"action": "deploy"})
    assert C.matches({"action": "read.logs"}, {"action": "read.*"})
    assert not C.matches({"action": "write"}, {"action": "read.*"})


def test_operators():
    assert C.matches({"params": {"env": "prod"}}, {"params.env": {"in": ["prod", "dev"]}})
    assert C.matches({"params": {"n": 5}}, {"params.n": {"gt": 3}})
    assert not C.matches({"params": {"n": 2}}, {"params.n": {"gt": 3}})
    assert C.matches({"params": {"irreversible": True}}, {"params.irreversible": {"eq": True}})
    assert C.matches({"x": "abc"}, {"x": {"exists": True}})
    assert C.matches({}, {"x": {"exists": False}})


def test_and_semantics():
    directive = {"action": "deploy", "params": {"env": "prod"}}
    assert C.matches(directive, {"action": "deploy", "params.env": "prod"})
    assert not C.matches(directive, {"action": "deploy", "params.env": "dev"})


def test_unknown_operator_raises():
    with pytest.raises(ValueError):
        C.matches({"x": 1}, {"x": {"approximately": 1}})

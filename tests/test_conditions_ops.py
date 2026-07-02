"""Tests for the expanded condition operators."""
import pytest

from sentinel_policy import conditions as c


def m(directive, match):
    return c.matches(directive, match)


# ---- regex --------------------------------------------------------------- #
def test_regex_matches_and_fails():
    assert m({"a": "db.drop"}, {"a": {"regex": r"^db\."}})
    assert not m({"a": "cache.drop"}, {"a": {"regex": r"^db\."}})


def test_regex_non_string_value_fails_closed():
    assert not m({"a": 5}, {"a": {"regex": r"\d+"}})


def test_regex_invalid_pattern_fails_closed():
    # an uncompilable pattern must not raise; it fails to match
    assert not m({"a": "x"}, {"a": {"regex": "("}})


def test_regex_cache_reuse():
    for _ in range(3):
        assert m({"a": "abc"}, {"a": {"regex": "a.c"}})
    assert "a.c" in c._RE_CACHE


# ---- startswith / endswith ---------------------------------------------- #
def test_startswith_endswith():
    assert m({"a": "prod-db"}, {"a": {"startswith": "prod"}})
    assert m({"a": "prod-db"}, {"a": {"endswith": "db"}})
    assert not m({"a": "prod-db"}, {"a": {"startswith": "dev"}})
    assert not m({"a": 3}, {"a": {"startswith": "x"}})


# ---- between ------------------------------------------------------------- #
@pytest.mark.parametrize("val,ok", [(5, True), (1, True), (10, True), (0, False), (11, False)])
def test_between_inclusive(val, ok):
    assert m({"n": val}, {"n": {"between": [1, 10]}}) is ok


def test_between_bad_operand_fails_closed():
    assert not m({"n": 5}, {"n": {"between": [1]}})
    assert not m({"n": "x"}, {"n": {"between": [1, 10]}})


# ---- length ------------------------------------------------------------- #
def test_len_operators():
    assert m({"xs": [1, 2, 3]}, {"xs": {"len_eq": 3}})
    assert m({"xs": [1, 2, 3]}, {"xs": {"len_gt": 2}})
    assert m({"xs": [1, 2, 3]}, {"xs": {"len_lt": 4}})
    assert not m({"xs": 5}, {"xs": {"len_gt": 0}})  # int has no len -> False


# ---- subset / superset -------------------------------------------------- #
def test_subset_superset():
    assert m({"scopes": ["read"]}, {"scopes": {"subset": ["read", "write"]}})
    assert not m({"scopes": ["admin"]}, {"scopes": {"subset": ["read", "write"]}})
    assert m({"scopes": ["read", "write"]}, {"scopes": {"superset": ["read"]}})
    assert not m({"scopes": "notalist"}, {"scopes": {"subset": ["read"]}})


# ---- cidr ---------------------------------------------------------------- #
def test_cidr_v4():
    assert m({"ip": "10.1.2.3"}, {"ip": {"cidr": "10.0.0.0/8"}})
    assert not m({"ip": "192.168.0.1"}, {"ip": {"cidr": "10.0.0.0/8"}})


def test_cidr_list_any():
    spec = {"ip": {"cidr": ["10.0.0.0/8", "192.168.0.0/16"]}}
    assert m({"ip": "192.168.5.5"}, spec)
    assert not m({"ip": "8.8.8.8"}, spec)


def test_cidr_v6_and_bad_value():
    assert m({"ip": "2001:db8::1"}, {"ip": {"cidr": "2001:db8::/32"}})
    assert not m({"ip": "not-an-ip"}, {"ip": {"cidr": "10.0.0.0/8"}})


# ---- time_window --------------------------------------------------------- #
def test_time_window_normal():
    assert m({"t": "12:00"}, {"t": {"time_window": "09:00-17:00"}})
    assert not m({"t": "18:00"}, {"t": {"time_window": "09:00-17:00"}})


def test_time_window_wrapping_midnight():
    spec = {"t": {"time_window": "22:00-06:00"}}
    assert m({"t": "23:30"}, spec)
    assert m({"t": "05:00"}, spec)
    assert not m({"t": "12:00"}, spec)


def test_time_window_seconds_and_bad_input():
    assert m({"t": "09:00:30"}, {"t": {"time_window": "09:00:00-09:01:00"}})
    assert not m({"t": "notatime"}, {"t": {"time_window": "09:00-17:00"}})
    assert not m({"t": "09:00"}, {"t": {"time_window": "malformed"}})


# ---- logical composition ------------------------------------------------- #
def test_all_any_not():
    assert m({"a": "prod"}, {"a": {"all_": [{"startswith": "pro"}, {"endswith": "od"}]}})
    assert not m({"a": "prod"}, {"a": {"all_": [{"startswith": "x"}]}})
    assert m({"a": "prod"}, {"a": {"any_": [{"eq": "dev"}, {"eq": "prod"}]}})
    assert m({"a": "prod"}, {"a": {"not_": {"eq": "dev"}}})
    assert not m({"a": "prod"}, {"a": {"not_": {"eq": "prod"}}})


def test_known_operators_includes_new_ops():
    ops = c.known_operators()
    for op in ("regex", "cidr", "time_window", "between", "subset",
               "superset", "startswith", "endswith", "all_", "any_", "not_"):
        assert op in ops


def test_unknown_operator_still_raises_in_matcher():
    with pytest.raises(ValueError):
        c.matches({"a": 1}, {"a": {"nope": 1}})

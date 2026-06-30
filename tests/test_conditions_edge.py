"""Edge-case and error-path tests for the condition matcher.

The matcher is the security-critical core: a condition that *silently* matches
(or silently fails to match) when it shouldn't is a policy bypass. These tests
pin the exact behavior at the boundaries.
"""
import pytest

from sentinel_policy import conditions as C


# ---- get_path -----------------------------------------------------------

def test_get_path_through_non_dict_returns_none():
    # a list is not traversable by a dotted key -> None, not an exception
    assert C.get_path({"a": [1, 2, 3]}, "a.b") is None


def test_get_path_root_missing():
    assert C.get_path({}, "anything") is None


def test_get_path_deep_nested():
    d = {"a": {"b": {"c": {"d": 42}}}}
    assert C.get_path(d, "a.b.c.d") == 42
    assert C.get_path(d, "a.b.c.e") is None


def test_get_path_value_is_none_vs_missing():
    # an explicit None is returned the same as missing (both None);
    # `exists` distinguishes intent at the operator level, not here
    assert C.get_path({"a": None}, "a") is None


# ---- empty match / catch-all -------------------------------------------

def test_empty_match_matches_everything():
    assert C.matches({"action": "anything"}, {})
    assert C.matches({}, {})


# ---- equality vs glob ---------------------------------------------------

def test_plain_string_is_equality_not_glob():
    assert C.matches({"a": "read.logs"}, {"a": "read.logs"})
    assert not C.matches({"a": "read.logs"}, {"a": "read.metrics"})


def test_glob_only_triggers_on_wildcard_chars():
    # no wildcard -> exact match; the literal "*" only matters when present
    assert C.matches({"a": "x"}, {"a": "*"})
    assert C.matches({"a": "anything"}, {"a": "*"})
    assert C.matches({"a": "read.x"}, {"a": "read.?"})


def test_glob_against_non_string_value_is_false():
    assert not C.matches({"a": 5}, {"a": "5*"})


def test_glob_operator_explicit():
    assert C.matches({"a": "secret/db"}, {"a": {"glob": "secret/*"}})
    assert not C.matches({"a": "public/db"}, {"a": {"glob": "secret/*"}})
    # glob operator on a non-string is False, never an exception
    assert not C.matches({"a": 7}, {"a": {"glob": "7"}})


# ---- in / nin -----------------------------------------------------------

def test_in_and_nin_membership():
    assert C.matches({"a": "prod"}, {"a": {"in": ["prod", "dev"]}})
    assert not C.matches({"a": "qa"}, {"a": {"in": ["prod", "dev"]}})
    assert C.matches({"a": "qa"}, {"a": {"nin": ["prod", "dev"]}})


def test_in_against_non_collection_operand_is_false():
    # an `in` whose operand is a bare int can never match -> False (and nin True)
    assert not C.matches({"a": 5}, {"a": {"in": 5}})
    assert C.matches({"a": 5}, {"a": {"nin": 5}})


def test_in_substring_on_string_operand():
    assert C.matches({"a": "ell"}, {"a": {"in": "hello"}})


# ---- contains -----------------------------------------------------------

def test_contains_on_list_and_string_and_dict():
    assert C.matches({"a": [1, 2, 3]}, {"a": {"contains": 2}})
    assert C.matches({"a": "hello"}, {"a": {"contains": "ell"}})
    assert C.matches({"a": {"k": "v"}}, {"a": {"contains": "k"}})  # key membership


def test_contains_on_none_is_false():
    assert not C.matches({}, {"a": {"contains": 1}})


# ---- exists -------------------------------------------------------------

def test_exists_true_and_false():
    assert C.matches({"a": "x"}, {"a": {"exists": True}})
    assert not C.matches({}, {"a": {"exists": True}})
    assert C.matches({}, {"a": {"exists": False}})
    assert not C.matches({"a": "x"}, {"a": {"exists": False}})


def test_exists_falsy_value_still_exists():
    # a present-but-falsy value (0, "", False) still "exists" only if not None;
    # the matcher uses `is not None`, so 0 counts as existing
    assert C.matches({"a": 0}, {"a": {"exists": True}})
    assert C.matches({"a": ""}, {"a": {"exists": True}})
    assert C.matches({"a": False}, {"a": {"exists": True}})


# ---- numeric comparisons ------------------------------------------------

def test_numeric_ops_full_set():
    assert C.matches({"n": 5}, {"n": {"gt": 3}})
    assert C.matches({"n": 5}, {"n": {"ge": 5}})
    assert C.matches({"n": 2}, {"n": {"lt": 3}})
    assert C.matches({"n": 3}, {"n": {"le": 3}})
    assert not C.matches({"n": 3}, {"n": {"gt": 3}})
    assert not C.matches({"n": 3}, {"n": {"lt": 3}})


def test_numeric_coercion_of_numeric_strings():
    # "5" coerces to 5.0 for comparison
    assert C.matches({"n": "5"}, {"n": {"gt": 3}})
    assert C.matches({"n": 5}, {"n": {"gt": "3"}})


def test_numeric_op_against_non_numeric_is_false_not_error():
    # comparing a word to a number must not raise; it just fails to match
    assert not C.matches({"n": "abc"}, {"n": {"gt": 3}})
    assert not C.matches({"n": None}, {"n": {"lt": 3}})
    assert not C.matches({"n": [1, 2]}, {"n": {"ge": 1}})


def test_bool_is_numeric_in_python_quirk():
    # documents that Python treats True as 1.0 in float(); pinned so a change
    # to numeric coercion is a deliberate, reviewed decision
    assert C.matches({"n": True}, {"n": {"ge": 1}})


# ---- AND semantics & operator stacking ---------------------------------

def test_multiple_operators_in_one_spec_are_anded():
    # 3 < n <= 10
    assert C.matches({"n": 5}, {"n": {"gt": 3, "le": 10}})
    assert not C.matches({"n": 11}, {"n": {"gt": 3, "le": 10}})
    assert not C.matches({"n": 3}, {"n": {"gt": 3, "le": 10}})


def test_multiple_fields_are_anded():
    d = {"action": "deploy", "params": {"env": "prod", "n": 9}}
    assert C.matches(d, {"action": "deploy", "params.env": "prod",
                         "params.n": {"gt": 5}})
    assert not C.matches(d, {"action": "deploy", "params.n": {"gt": 50}})


# ---- unknown operator raises -------------------------------------------

def test_unknown_operator_raises_value_error_with_name():
    with pytest.raises(ValueError) as ei:
        C.matches({"x": 1}, {"x": {"nonesuch": 1}})
    assert "nonesuch" in str(ei.value)


def test_known_operators_set_is_complete():
    expected = {"eq", "ne", "in", "nin", "glob", "contains", "exists",
                "gt", "ge", "lt", "le"}
    assert C.known_operators() == expected

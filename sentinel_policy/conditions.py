"""A small, safe matcher for policy conditions.

A rule's `match` is a mapping of (dotted field path) -> (expected). The expected
value is either a scalar — matched by equality, or by glob if it contains
wildcard characters — or an operator object like {"in": [...]}, {"gt": 5},
{"exists": true}. All conditions in a match must hold (logical AND).

There is no `eval` and no expression language here on purpose: policy files are
data, not code, so they can be reviewed, diffed, and signed without executing
anything.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

_WILDCARD = set("*?[]")


def get_path(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _num(a: Any, b: Any):
    try:
        return float(a), float(b)
    except (TypeError, ValueError):
        return None


_OPS = {
    "eq": lambda v, o: v == o,
    "ne": lambda v, o: v != o,
    "in": lambda v, o: v in o if isinstance(o, (list, tuple, set, str)) else False,
    "nin": lambda v, o: v not in o if isinstance(o, (list, tuple, set, str)) else True,
    "glob": lambda v, o: isinstance(v, str) and fnmatch(v, str(o)),
    "contains": lambda v, o: o in v if isinstance(v, (list, tuple, set, str, dict)) else False,
    "exists": lambda v, o: (v is not None) == bool(o),
    "gt": lambda v, o: (lambda p: p is not None and p[0] > p[1])(_num(v, o)),
    "ge": lambda v, o: (lambda p: p is not None and p[0] >= p[1])(_num(v, o)),
    "lt": lambda v, o: (lambda p: p is not None and p[0] < p[1])(_num(v, o)),
    "le": lambda v, o: (lambda p: p is not None and p[0] <= p[1])(_num(v, o)),
}


def known_operators() -> set[str]:
    return set(_OPS)


def _match_one(value: Any, spec: Any) -> bool:
    if isinstance(spec, dict):
        for op, operand in spec.items():
            fn = _OPS.get(op)
            if fn is None:
                raise ValueError(f"unknown condition operator: {op!r}")
            if not fn(value, operand):
                return False
        return True
    if isinstance(spec, str) and any(c in _WILDCARD for c in spec):
        return isinstance(value, str) and fnmatch(value, spec)
    return value == spec


def matches(directive: dict, match: dict) -> bool:
    for field, spec in match.items():
        if not _match_one(get_path(directive, field), spec):
            return False
    return True

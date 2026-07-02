"""A small, safe matcher for policy conditions.

A rule's `match` is a mapping of (dotted field path) -> (expected). The expected
value is either a scalar — matched by equality, or by glob if it contains
wildcard characters — or an operator object like {"in": [...]}, {"gt": 5},
{"exists": true}. All conditions in a match must hold (logical AND).

There is no `eval` and no expression language here on purpose: policy files are
data, not code, so they can be reviewed, diffed, and signed without executing
anything.

Operators
---------
Equality / sets:   eq, ne, in, nin, contains, subset, superset
Text:              glob, regex, startswith, endswith
Numeric:          gt, ge, lt, le, between
Presence / size:  exists, len_eq, len_gt, len_lt
Network:          cidr        (is the value's IP inside the given CIDR block?)
Time:             time_window (is HH:MM[:SS] inside "start-end", wrapping midnight ok?)
Logical:          all_, any_, not_   (compose sub-specs on the *same* field value)

Every operator is total: given any value it returns True or False, never raises
for a type mismatch — a governance gate must fail closed, not crash.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import time as _time
from fnmatch import fnmatch
from typing import Any

_WILDCARD = set("*?[]")

# bound the size of a compiled-regex cache so a pathological policy can't grow
# memory without limit; policies are small so this is generous.
_RE_CACHE: "dict[str, re.Pattern]" = {}
_RE_CACHE_MAX = 512


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


def _compile(pattern: Any) -> "re.Pattern | None":
    if not isinstance(pattern, str):
        return None
    cached = _RE_CACHE.get(pattern)
    if cached is not None:
        return cached
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None
    if len(_RE_CACHE) < _RE_CACHE_MAX:
        _RE_CACHE[pattern] = compiled
    return compiled


def _parse_clock(text: Any) -> "_time | None":
    """Parse 'HH:MM' or 'HH:MM:SS' into a datetime.time (24h). None if invalid."""
    if isinstance(text, _time):
        return text
    if not isinstance(text, str):
        return None
    parts = text.strip().split(":")
    if len(parts) not in (2, 3):
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    h, m = nums[0], nums[1]
    s = nums[2] if len(nums) == 3 else 0
    if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s < 60):
        return None
    return _time(h, m, s)


def _op_time_window(value: Any, operand: Any) -> bool:
    """operand is "start-end" (e.g. "09:00-17:00"); value is a clock string.

    A window whose end is <= start is treated as wrapping past midnight
    (e.g. "22:00-06:00" is the overnight window).
    """
    if not isinstance(operand, str) or "-" not in operand:
        return False
    start_s, end_s = operand.split("-", 1)
    start, end = _parse_clock(start_s), _parse_clock(end_s)
    now = _parse_clock(value)
    if start is None or end is None or now is None:
        return False
    if start <= end:
        return start <= now <= end
    # wrapping window: inside if after start OR before end
    return now >= start or now <= end


def _op_cidr(value: Any, operand: Any) -> bool:
    """Is the IP in `value` contained in the CIDR block(s) in `operand`?

    operand may be a single CIDR string or a list of them (match = any).
    """
    if isinstance(operand, (list, tuple, set)):
        return any(_op_cidr(value, o) for o in operand)
    try:
        addr = ipaddress.ip_address(str(value))
        net = ipaddress.ip_network(str(operand), strict=False)
    except ValueError:
        return False
    return addr in net


def _op_between(value: Any, operand: Any) -> bool:
    """operand is [lo, hi]; inclusive numeric range."""
    if not isinstance(operand, (list, tuple)) or len(operand) != 2:
        return False
    lo = _num(value, operand[0])
    hi = _num(value, operand[1])
    if lo is None or hi is None:
        return False
    return lo[1] <= lo[0] <= hi[1]


def _length(value: Any):
    try:
        return len(value)
    except TypeError:
        return None


def _op_len(value: Any, operand: Any, cmp) -> bool:
    n = _length(value)
    if n is None:
        return False
    try:
        target = int(operand)
    except (TypeError, ValueError):
        return False
    return cmp(n, target)


def _as_set(x: Any):
    if isinstance(x, (list, tuple, set)):
        try:
            return set(x)
        except TypeError:
            return None
    return None


def _op_subset(value: Any, operand: Any) -> bool:
    a, b = _as_set(value), _as_set(operand)
    return a is not None and b is not None and a <= b


def _op_superset(value: Any, operand: Any) -> bool:
    a, b = _as_set(value), _as_set(operand)
    return a is not None and b is not None and a >= b


def _op_all(value: Any, operand: Any) -> bool:
    """operand is a list of sub-specs; every one must match `value`."""
    if not isinstance(operand, (list, tuple)):
        return False
    return all(_match_one(value, spec) for spec in operand)


def _op_any(value: Any, operand: Any) -> bool:
    if not isinstance(operand, (list, tuple)):
        return False
    return any(_match_one(value, spec) for spec in operand)


def _op_not(value: Any, operand: Any) -> bool:
    return not _match_one(value, operand)


_OPS = {
    "eq": lambda v, o: v == o,
    "ne": lambda v, o: v != o,
    "in": lambda v, o: v in o if isinstance(o, (list, tuple, set, str)) else False,
    "nin": lambda v, o: v not in o if isinstance(o, (list, tuple, set, str)) else True,
    "glob": lambda v, o: isinstance(v, str) and fnmatch(v, str(o)),
    "regex": lambda v, o: isinstance(v, str) and (lambda p: p is not None and p.search(v) is not None)(_compile(o)),
    "startswith": lambda v, o: isinstance(v, str) and isinstance(o, str) and v.startswith(o),
    "endswith": lambda v, o: isinstance(v, str) and isinstance(o, str) and v.endswith(o),
    "contains": lambda v, o: o in v if isinstance(v, (list, tuple, set, str, dict)) else False,
    "subset": _op_subset,
    "superset": _op_superset,
    "exists": lambda v, o: (v is not None) == bool(o),
    "gt": lambda v, o: (lambda p: p is not None and p[0] > p[1])(_num(v, o)),
    "ge": lambda v, o: (lambda p: p is not None and p[0] >= p[1])(_num(v, o)),
    "lt": lambda v, o: (lambda p: p is not None and p[0] < p[1])(_num(v, o)),
    "le": lambda v, o: (lambda p: p is not None and p[0] <= p[1])(_num(v, o)),
    "between": _op_between,
    "len_eq": lambda v, o: _op_len(v, o, lambda a, b: a == b),
    "len_gt": lambda v, o: _op_len(v, o, lambda a, b: a > b),
    "len_lt": lambda v, o: _op_len(v, o, lambda a, b: a < b),
    "cidr": _op_cidr,
    "time_window": _op_time_window,
    "all_": _op_all,
    "any_": _op_any,
    "not_": _op_not,
}

# operators whose operand must be a collection to be well-formed (used by lint)
COLLECTION_OPS = frozenset({"in", "nin", "subset", "superset", "all_", "any_"})
# operators whose operand must be a two-element range
RANGE_OPS = frozenset({"between"})


def known_operators() -> "set[str]":
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

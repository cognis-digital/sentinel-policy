"""Scenario 8 - platform: loading a malformed policy fails loudly and clearly.

A governance gate must never *silently* load a half-broken policy. This demo
feeds several malformed inputs to `Policy.from_dict` and shows that each raises
a `PolicyError` whose message names the offending rule and field - the operator
gets a fix-it message, not a traceback. `PolicyError` subclasses `ValueError`,
so existing handlers keep working.
"""
from _common import banner
from sentinel_policy import Policy, PolicyError


BAD_INPUTS = [
    ("rule missing 'effect'",
     {"name": "p", "rules": [{"id": "r1", "match": {}}]}),
    ("invalid effect value",
     {"name": "p", "rules": [{"id": "r2", "effect": "maybe", "match": {}}]}),
    ("'rules' is not a list",
     {"name": "p", "rules": {"oops": True}}),
    ("'match' is not an object",
     {"name": "p", "rules": [{"id": "r3", "effect": "allow", "match": [1, 2]}]}),
    ("non-integer priority",
     {"name": "p", "rules": [{"id": "r4", "effect": "allow", "match": {},
                              "priority": "high"}]}),
    ("bad default effect",
     {"name": "p", "default": "perhaps", "rules": []}),
]


def main() -> None:
    banner("MALFORMED POLICY ERRORS  -  fail loud, name the field")

    print()
    for label, data in BAD_INPUTS:
        try:
            Policy.from_dict(data)
        except PolicyError as exc:
            print(f"  PolicyError  [{label}]")
            print(f"               {exc}")
        else:
            raise AssertionError(f"{label!r} should have raised PolicyError")

    # PolicyError is a ValueError: legacy `except ValueError` still catches it.
    try:
        Policy.from_dict({"name": "p", "rules": [{"id": "z", "match": {}}]})
    except ValueError:
        print("\n  PolicyError is a ValueError - existing handlers stay valid.")

    print("\nEvery malformed policy was rejected with a message an operator can")
    print("act on, before a single decision was ever rendered.")


if __name__ == "__main__":
    main()

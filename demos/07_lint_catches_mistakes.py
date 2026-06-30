"""Scenario 7 - platform: the linter catches policy mistakes before they ship.

`Policy.validate()` reports *all* problems at once (it returns a list, it does
not raise), so a CI step can fail a bad policy with a readable report. This demo
builds a deliberately broken policy and prints every problem the linter finds,
then shows the corrected policy validating clean.
"""
from _common import banner
from sentinel_policy import Policy


BROKEN = {
    "name": "broken-controls", "default": "deny",
    "rules": [
        # cites a principle that does not exist
        {"id": "r1", "doctrine": "S42", "effect": "deny",
         "match": {"action": "x"}},
        # unknown operator - typo for "in"
        {"id": "r2", "effect": "allow", "match": {"params.env": {"on": ["dev"]}}},
        # `in` with a non-list operand can never match
        {"id": "r3", "effect": "deny", "match": {"params.n": {"in": 5}}},
        # require_approval with no tier - reviewer can't see the escalation level
        {"id": "r4", "effect": "require_approval", "match": {"action": "deploy"}},
        # duplicate id shadows the earlier rule
        {"id": "r1", "effect": "allow", "match": {"action": "y"}},
    ],
}

FIXED = {
    "name": "fixed-controls", "default": "deny",
    "rules": [
        {"id": "deny-x", "doctrine": "S2", "effect": "deny",
         "match": {"action": "x"}},
        {"id": "allow-dev", "doctrine": "S2", "effect": "allow",
         "match": {"params.env": {"in": ["dev"]}}},
        {"id": "gate-deploy", "doctrine": "S3", "effect": "require_approval",
         "tier": "high", "match": {"action": "deploy"}},
    ],
}


def main() -> None:
    banner("LINT CATCHES MISTAKES  -  fail the bad policy in CI, not in prod")

    broken = Policy.from_dict(BROKEN)
    problems = broken.validate()
    print(f"\nLinting '{broken.name}' - {len(problems)} problem(s):\n")
    for p in problems:
        print(f"  x {p}")

    fixed = Policy.from_dict(FIXED)
    print(f"\nLinting the corrected '{fixed.name}': "
          f"{'OK (clean)' if fixed.validate() == [] else 'still broken'}")

    assert problems, "broken policy must report problems"
    assert fixed.validate() == [], "fixed policy must be clean"

    print("\nThe linter reports every problem at once and never executes the")
    print("policy - it is data, so reviewing it is reading, not running.")


if __name__ == "__main__":
    main()

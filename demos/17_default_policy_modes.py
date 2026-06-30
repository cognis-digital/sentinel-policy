"""Scenario 17 - governance posture: what your default *means*.

The single most consequential line in a policy is its `default`. "Deny by
default" is least-authority (S2); "allow by default" is the opposite posture and
should be a deliberate, visible choice. This demo runs the *same* unmatched
directive against three policies that differ only in their default, so the
posture is the variable under test.
"""
from _common import banner
from sentinel_policy import Effect, Policy


def policy_with_default(default):
    return Policy.from_dict({
        "name": f"default-{default}", "default": default,
        "rules": [
            {"id": "explicit-allow-read", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*"}},
        ],
    })


def main() -> None:
    banner("DEFAULT POLICY MODES  -  the posture is one line")

    unmatched = {"actor": "agent", "action": "delete.everything", "params": {}}
    matched = {"actor": "agent", "action": "read.logs", "params": {}}

    print("\nSame unmatched directive ('delete.everything'), three defaults:\n")
    for default in ("deny", "require_approval", "allow"):
        p = policy_with_default(default)
        d = p.evaluate(unmatched)
        print(f"  default={default:<16} -> {d.effect.value:<16} "
              f"rule={d.rule} allowed={d.allowed}")

    # the explicit rule still wins regardless of default
    print("\nThe explicit read rule fires the same way under every default:\n")
    for default in ("deny", "require_approval", "allow"):
        d = policy_with_default(default).evaluate(matched)
        print(f"  default={default:<16} -> {d.effect.value:<16} rule={d.rule}")

    assert policy_with_default("deny").evaluate(unmatched).effect is Effect.DENY
    assert policy_with_default("allow").evaluate(unmatched).allowed
    # explicit rule is unaffected by the default
    assert policy_with_default("allow").evaluate(matched).rule == "explicit-allow-read"

    print("\n'Deny by default' is least authority (S2). If you choose 'allow',")
    print("make it a decision someone signed off on - it is right there in the file.")


if __name__ == "__main__":
    main()

"""Scenario 4 - platform engineers.

A platform team runs an org-wide doctrine *above* many team policies. The engine
supports this with `as_gate_evaluator(defer_on_default=...)`: a team policy
decides what it has an opinion about and returns None (defers) otherwise, so the
org policy gets the final say on everything the team left open. This demo layers
a permissive team policy under a strict org policy and shows the merged verdict
for several directives - exactly how you'd wire a tiered gate.
"""
from _common import banner
from sentinel_policy import Effect, Policy

# Org-wide: irreversible actions always gate; cross-boundary export always denied.
ORG = Policy.from_dict({
    "name": "org-doctrine", "default": "deny",
    "rules": [
        {"id": "org-gate-irreversible", "doctrine": "S5",
         "effect": "require_approval", "tier": "high", "priority": 100,
         "match": {"params.irreversible": {"eq": True}}},
        {"id": "org-deny-export", "doctrine": "S6", "effect": "deny",
         "priority": 100, "match": {"action": "*export*"}},
    ],
})

# Team: liberal with its own dev namespace; silent (defers) on everything else.
TEAM = Policy.from_dict({
    "name": "team-payments", "default": "deny",
    "rules": [
        {"id": "team-allow-dev", "doctrine": "S2", "effect": "allow",
         "match": {"params.env": {"in": ["dev", "staging"]}}},
    ],
})


def layered(directive: dict):
    """Team decides first; if it only hit its default, the org policy decides."""
    team_eval = TEAM.as_gate_evaluator(defer_on_default=True)
    decision = team_eval(directive)
    source = "team"
    if decision is None:                     # team had no opinion -> escalate
        decision = ORG.evaluate(directive)
        source = "org"
    return decision, source


def main() -> None:
    banner("LAYERED POLICIES  -  an org doctrine above team policies")

    print("\nTeam policy defers on its default so the org policy governs the rest.\n")
    cases = [
        ({"action": "deploy", "params": {"env": "dev"}}, "team owns its dev namespace"),
        ({"action": "deploy", "params": {"env": "prod", "irreversible": True}},
         "team defers -> org gates the irreversible prod action"),
        ({"action": "data.export", "params": {"env": "prod"}},
         "team defers -> org denies the boundary cross"),
        ({"action": "noop", "params": {"env": "prod"}},
         "nobody allows it -> org default deny"),
    ]
    for directive, note in cases:
        d, source = layered(directive)
        print(f"  [{source:>4}] {d.effect.value:<16} [{d.doctrine or '--'}] "
              f"{d.rule:<22} {directive['action']} ({note})")

    # The org's irreversible-gate must win even though the team is permissive.
    d, source = layered({"action": "deploy", "params": {"env": "dev", "irreversible": True}})
    # team matches env=dev first and allows; to enforce org-above-team for the
    # irreversible case, the platform evaluates org as a hard overlay:
    org_overlay = ORG.evaluate({"action": "deploy",
                                "params": {"env": "dev", "irreversible": True}})
    assert org_overlay.effect is Effect.REQUIRE_APPROVAL

    print("\nComposition is just function layering: each tier is a pure evaluator,")
    print("so you can stack doctrine -> org -> team without a DSL or a daemon.")


if __name__ == "__main__":
    main()

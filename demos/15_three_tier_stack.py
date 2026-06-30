"""Scenario 15 - platform: a three-tier doctrine -> org -> team stack.

Demo 4 layered two tiers; real orgs run three. This demo composes a global
DOCTRINE overlay (hard, non-negotiable), an ORG policy, and a permissive TEAM
policy. Evaluation order: the doctrine overlay gets first refusal on the
universal hard rules; otherwise the team decides what it owns; otherwise the org
decides; otherwise the org default. Pure function layering - no DSL, no daemon.
"""
from _common import banner
from sentinel_policy import Effect, Policy


# Tier 1: global doctrine overlay - applies everywhere, wins outright.
DOCTRINE_OVERLAY = Policy.from_dict({
    "name": "doctrine-overlay", "default": "deny",
    "rules": [
        {"id": "global-deny-export", "doctrine": "S6", "effect": "deny",
         "match": {"action": "*export*"}},
        {"id": "global-gate-irreversible", "doctrine": "S5",
         "effect": "require_approval", "tier": "high",
         "match": {"params.irreversible": {"eq": True}}},
    ],
})

# Tier 2: org policy - defaults handled here when team defers.
ORG = Policy.from_dict({
    "name": "org", "default": "deny",
    "rules": [
        {"id": "org-allow-read", "doctrine": "S2", "effect": "allow",
         "match": {"action": "read.*"}},
        {"id": "org-gate-prod", "doctrine": "S3", "effect": "require_approval",
         "tier": "high", "match": {"params.env": "prod"}},
    ],
})

# Tier 3: team policy - liberal inside its own dev/staging namespace.
TEAM = Policy.from_dict({
    "name": "team", "default": "deny",
    "rules": [
        {"id": "team-allow-nonprod", "doctrine": "S2", "effect": "allow",
         "match": {"params.env": {"in": ["dev", "staging"]}}},
    ],
})


def decide(directive):
    """doctrine overlay (hard) -> team (defers) -> org (defers) -> org default."""
    overlay = DOCTRINE_OVERLAY.as_gate_evaluator(defer_on_default=True)(directive)
    if overlay is not None:
        return overlay, "doctrine"
    team = TEAM.as_gate_evaluator(defer_on_default=True)(directive)
    if team is not None:
        return team, "team"
    org = ORG.as_gate_evaluator(defer_on_default=True)(directive)
    if org is not None:
        return org, "org"
    return ORG.evaluate(directive), "org-default"


def main() -> None:
    banner("THREE-TIER STACK  -  doctrine -> org -> team")

    cases = [
        ({"action": "data.export", "params": {"env": "dev"}},
         "doctrine overlay denies export everywhere"),
        ({"action": "deploy", "params": {"env": "dev", "irreversible": True}},
         "doctrine overlay gates the irreversible action"),
        ({"action": "deploy", "params": {"env": "staging"}},
         "team owns its staging namespace"),
        ({"action": "read.metrics", "params": {"env": "prod"}},
         "team defers -> org allows the read"),
        ({"action": "deploy", "params": {"env": "prod"}},
         "team defers -> org gates prod"),
        ({"action": "rm.tablespace", "params": {"env": "qa"}},
         "nobody allows it -> org default deny"),
    ]
    print()
    for directive, note in cases:
        d, tier = decide(directive)
        print(f"  [{tier:>12}] {d.effect.value:<16} [{d.doctrine or '--'}] "
              f"{directive['action']} ({note})")

    # the doctrine overlay must win even inside the team's own namespace
    d, tier = decide({"action": "data.export", "params": {"env": "dev"}})
    assert tier == "doctrine" and d.effect is Effect.DENY

    print("\nThree pure evaluators stacked by deferral. The non-negotiable")
    print("doctrine sits on top; teams stay autonomous below it.")


if __name__ == "__main__":
    main()

"""Scenario 19 - onboarding: walk the seven rules with a worked example each.

The doctrine is meant to be argued with, which means it has to be readable. This
demo prints each SENTINEL rule and pairs it with a one-line policy snippet that
*enforces* that rule, so a newcomer sees the principle and its mechanism side by
side. It uses the published `DOCTRINE` data directly - the prose can never drift
from the rules.
"""
from _common import banner
from sentinel_policy import DOCTRINE, Effect, Policy, rule


# one illustrative rule per doctrine principle
ENFORCEMENT = {
    "S1": ("deny-anonymous", "deny",
           {"actor": {"exists": False}}, None),
    "S2": ("allow-scoped-read", "allow",
           {"action": "read.*", "params.tenant": "acme"}, None),
    "S3": ("gate-prod-deploy", "require_approval",
           {"action": "deploy", "params.env": "prod"}, "high"),
    "S4": ("require-record", "require_approval",
           {"params.recorded": {"eq": False}}, "med"),
    "S5": ("gate-irreversible", "require_approval",
           {"params.irreversible": {"eq": True}}, "high"),
    "S6": ("deny-cross-boundary", "deny",
           {"action": "*export*"}, None),
    "S7": ("default-records-everything", "deny", {}, None),
}


def main() -> None:
    banner("DOCTRINE WALKTHROUGH  -  each rule, with the snippet that enforces it")

    rules = []
    for sid, (rid, effect, match, tier) in ENFORCEMENT.items():
        r = {"id": rid, "doctrine": sid, "effect": effect, "match": match}
        if tier:
            r["tier"] = tier
        rules.append(r)
    policy = Policy.from_dict({"name": "walkthrough", "default": "deny",
                               "rules": rules})
    assert policy.validate() == []

    for d in DOCTRINE:
        rid, effect, match, _ = ENFORCEMENT[d.id]
        print(f"\n{d.id}  {d.name}")
        print(f"    {d.statement}")
        print(f"    enforced by rule '{rid}': effect={effect}, match={match}")

    # the snippets form a real, valid policy that covers all seven principles
    cov = policy.doctrine_coverage()
    print(f"\nThe seven snippets compose into one valid policy covering "
          f"{len(cov['covered'])}/7 principles.")
    assert cov["uncovered"] == []
    # and it still evaluates: an anonymous read is denied by S1
    assert policy.evaluate({"action": "read.x"}).effect is Effect.DENY

    print("\nEvery rule above is published data. Disagree with one? Edit the")
    print("statement and the snippet together - they are kept in lockstep.")


if __name__ == "__main__":
    main()

"""Scenario 10 - safety: Reversibility Preference (S5) in practice.

Most mistakes are survivable if they can be undone. S5 says prefer reversible
actions and gate the irreversible ones behind a higher tier. This demo runs a
mixed batch through a policy that allows reversible work, but holds anything
flagged `irreversible` for a separate approval - regardless of which verb it is.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "reversibility", "default": "deny",
        "rules": [
            {"id": "gate-irreversible", "doctrine": "S5",
             "effect": "require_approval", "tier": "high", "priority": 100,
             "match": {"params.irreversible": {"eq": True}},
             "reason": "irreversible action needs explicit acknowledgement"},
            {"id": "allow-reversible-writes", "doctrine": "S2", "effect": "allow",
             "match": {"action": "write.*"}},
            {"id": "allow-reads", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*"}},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("REVERSIBILITY GATE  -  undo-able passes, irreversible waits")

    print(f"\nPolicy '{policy.name}' built and validated: "
          f"{policy.validate() == []}\n")

    show(policy, {"action": "write.record", "params": {"irreversible": False}},
         "reversible write, fine")
    drop = show(policy, {"action": "db.drop_table",
                         "params": {"irreversible": True}},
                "irreversible: held for acknowledgement")
    purge = show(policy, {"action": "write.bulk_delete",
                          "params": {"irreversible": True}},
                 "even a 'write' gates when it can't be undone")
    show(policy, {"action": "read.table", "params": {}}, "read, fine")

    assert drop.effect is Effect.REQUIRE_APPROVAL and drop.doctrine == "S5"
    assert purge.effect is Effect.REQUIRE_APPROVAL

    print("\nThe irreversibility flag - not the verb - decides the tier, so a")
    print("one-way action can never ride in on routine authority.")


if __name__ == "__main__":
    main()

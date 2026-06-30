"""Scenario 9 - security: when rules conflict, priority is the tie-breaker.

Real policies have overlapping rules: a broad allow and a narrow deny on the
same action. The engine resolves this deterministically - highest priority
first, then declaration order - so the *targeted* control wins over the broad
one. This demo shows a deny outranking an allow for one specific action while
the broad allow still governs everything else.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "conflict-resolution", "default": "deny",
        "rules": [
            # broad: all reads are fine (low priority)
            {"id": "allow-all-reads", "doctrine": "S2", "effect": "allow",
             "priority": 1, "match": {"action": "read.*"}},
            # narrow + high priority: but never read the crown-jewels table
            {"id": "deny-read-secrets", "doctrine": "S6", "effect": "deny",
             "priority": 100, "match": {"action": "read.secrets"},
             "reason": "secrets table is above the read tier"},
            # narrow + high priority: bulk reads gate for approval
            {"id": "gate-bulk-read", "doctrine": "S3", "effect": "require_approval",
             "tier": "med", "priority": 50,
             "match": {"action": "read.*", "params.rows": {"gt": 10000}}},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("PRIORITY CONFLICT RESOLUTION  -  the targeted rule wins")

    assert policy.validate() == []
    print(f"\nPolicy '{policy.name}': broad allow + two high-priority overrides.\n")

    routine = show(policy, {"action": "read.logs", "params": {"rows": 12}},
                   "broad allow governs the ordinary case")
    secret = show(policy, {"action": "read.secrets", "params": {"rows": 1}},
                  "high-priority deny outranks the broad allow")
    bulk = show(policy, {"action": "read.events", "params": {"rows": 50000}},
                "bulk read trips the approval gate")

    assert routine.effect is Effect.ALLOW and routine.rule == "allow-all-reads"
    assert secret.effect is Effect.DENY and secret.rule == "deny-read-secrets"
    assert bulk.effect is Effect.REQUIRE_APPROVAL

    print("\nSame verb (read), three verdicts - decided by priority and the exact")
    print("match, not by the order someone happened to type the rules in.")


if __name__ == "__main__":
    main()

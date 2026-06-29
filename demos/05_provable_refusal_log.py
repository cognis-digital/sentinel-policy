"""Scenario 5 - safety / SRE on call.

Provable Refusal (S7): a denied or aborted action must be recorded with the rule
and reason - silence is not an outcome. The engine gives you a structured
`Decision` for *every* directive (including the default branch), so building a
refusal log is just serializing decisions. This demo runs a batch of agent
directives through the policy and emits an audit-shaped record for each, then
summarizes how many were allowed, gated, or refused, and why.
"""
import json

from _common import banner, example_policy
from sentinel_policy import Effect


def main() -> None:
    policy = example_policy()
    banner("PROVABLE REFUSAL  -  no silent denials, everything is a record")

    directives = [
        {"actor": "alice", "action": "read.logs", "params": {}},
        {"actor": "bob", "action": "deploy", "params": {"env": "prod"}},
        {"actor": "carol", "action": "db.drop", "params": {"irreversible": True}},
        {"actor": "etl", "action": "pii.export", "params": {}},
        {"actor": "dave", "action": "rotate.keys", "params": {}},
    ]

    counts = {Effect.ALLOW: 0, Effect.DENY: 0, Effect.REQUIRE_APPROVAL: 0}
    print("\nDecision log (one structured record per directive):\n")
    for d in directives:
        decision = policy.evaluate(d)
        counts[decision.effect] += 1
        record = {
            "actor": d["actor"],
            "action": d["action"],
            **decision.as_dict(),   # allowed / effect / rule / doctrine / reason / obligations
        }
        print("  " + json.dumps(record, separators=(",", ": ")))

    print("\nSummary:")
    print(f"  allowed          : {counts[Effect.ALLOW]}")
    print(f"  require-approval : {counts[Effect.REQUIRE_APPROVAL]}")
    print(f"  denied/default   : {counts[Effect.DENY]}")

    # Every directive produced a record with a named rule - none fell silent.
    assert sum(counts.values()) == len(directives)
    print("\nEvery action - allowed or refused - left a record naming the rule that")
    print("decided it. That is what makes a refusal you can prove to an auditor.")


if __name__ == "__main__":
    main()

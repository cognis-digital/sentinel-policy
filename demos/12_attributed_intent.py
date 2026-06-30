"""Scenario 12 - governance: Attributed Intent (S1).

S1: every action traces to a named, authenticated operator. A directive with no
actor (or an explicitly anonymous one) is the root of the "who told the agent to
do that?" problem. This demo denies unattributed directives up front, allows a
named operator's routine work, and still gates a named operator's risky work -
attribution is necessary, not sufficient.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "attributed-intent", "default": "deny",
        "rules": [
            # no actor at all -> deny (S1)
            {"id": "deny-anonymous", "doctrine": "S1", "effect": "deny",
             "priority": 100, "match": {"actor": {"exists": False}},
             "reason": "every action must name an authenticated operator"},
            # the placeholder 'unknown' actor is also unattributed
            {"id": "deny-unknown-actor", "doctrine": "S1", "effect": "deny",
             "priority": 100, "match": {"actor": "unknown"},
             "reason": "placeholder actor is not an attribution"},
            # a named operator may do routine reads
            {"id": "allow-named-read", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*"}},
            # but risky work still gates even with a name
            {"id": "gate-named-deploy", "doctrine": "S3",
             "effect": "require_approval", "tier": "high", "priority": 10,
             "match": {"action": "deploy"}},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("ATTRIBUTED INTENT  -  no name, no action")

    assert policy.validate() == []
    print(f"\nPolicy '{policy.name}': attribution required, then scope, then tier.\n")

    anon = show(policy, {"action": "read.logs", "params": {}},
                "no actor key -> denied")
    placeholder = show(policy, {"actor": "unknown", "action": "read.logs"},
                       "placeholder actor -> denied")
    named = show(policy, {"actor": "alice", "action": "read.logs"},
                 "named operator, routine read -> allowed")
    deploy = show(policy, {"actor": "alice", "action": "deploy"},
                  "named, but risky -> still gated")

    assert anon.effect is Effect.DENY and anon.doctrine == "S1"
    assert placeholder.effect is Effect.DENY
    assert named.effect is Effect.ALLOW
    assert deploy.effect is Effect.REQUIRE_APPROVAL

    print("\nAttribution is the floor, not the ceiling: a name lets you act, the")
    print("rest of the doctrine still decides how far.")


if __name__ == "__main__":
    main()

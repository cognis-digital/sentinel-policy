"""Scenario 11 - finance/ops: numeric thresholds gate by magnitude.

The matcher's numeric operators (`gt`/`ge`/`lt`/`le`) let a policy reason about
*how much*, not just *what*. This demo gates spend by dollar amount: small spends
auto-approve, mid-size spends gate, and anything over a hard ceiling is denied -
and a non-numeric amount fails the comparison safely (falls to default) rather
than slipping through.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "spend-controls", "default": "deny",
        "rules": [
            {"id": "deny-over-ceiling", "doctrine": "S3", "effect": "deny",
             "priority": 100, "match": {"params.usd": {"gt": 100000}},
             "reason": "above the hard spend ceiling"},
            {"id": "gate-mid-spend", "doctrine": "S3",
             "effect": "require_approval", "tier": "high", "priority": 50,
             "match": {"action": "spend", "params.usd": {"ge": 1000}},
             "reason": "mid-size spend needs a second signer"},
            {"id": "allow-small-spend", "doctrine": "S2", "effect": "allow",
             "match": {"action": "spend", "params.usd": {"lt": 1000}}},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("NUMERIC THRESHOLDS  -  gate by magnitude, not just verb")

    assert policy.validate() == []
    print(f"\nPolicy '{policy.name}': <$1k auto, $1k-$100k gated, >$100k denied.\n")

    small = show(policy, {"action": "spend", "params": {"usd": 250}},
                 "petty cash, auto-approved")
    mid = show(policy, {"action": "spend", "params": {"usd": 5000}},
               "second signer required")
    big = show(policy, {"action": "spend", "params": {"usd": 250000}},
               "over the ceiling, denied")
    junk = show(policy, {"action": "spend", "params": {"usd": "lots"}},
                "non-numeric amount: comparison fails safe -> default deny")

    assert small.effect is Effect.ALLOW
    assert mid.effect is Effect.REQUIRE_APPROVAL
    assert big.effect is Effect.DENY
    assert junk.rule == "default"  # never silently allowed

    print("\nA malformed amount does not slip through: a numeric op against a")
    print("non-number is False, so the directive falls to the policy default.")


if __name__ == "__main__":
    main()

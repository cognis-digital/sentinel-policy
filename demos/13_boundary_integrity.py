"""Scenario 13 - security: Boundary Integrity (S6) across tenants & networks.

Exfiltration and privilege bleed almost always look like an un-checked boundary
cross. This demo encodes three boundaries - tenant, data classification, and
network egress - and shows the engine denying each illegitimate crossing while
allowing the in-boundary equivalents.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "boundary-integrity", "default": "deny",
        "rules": [
            # classified data may not leave to an external destination
            {"id": "deny-classified-egress", "doctrine": "S6", "effect": "deny",
             "priority": 100,
             "match": {"params.classification": "secret",
                       "params.dest": {"glob": "external/*"}},
             "reason": "classified data may not cross to an external boundary"},
            # no reading another tenant's data
            {"id": "deny-cross-tenant", "doctrine": "S6", "effect": "deny",
             "priority": 90,
             "match": {"action": "read.*", "params.tenant": {"ne": "acme"}},
             "reason": "no reading across a tenant boundary"},
            # any egress to the public internet gates
            {"id": "gate-public-egress", "doctrine": "S6",
             "effect": "require_approval", "tier": "high", "priority": 50,
             "match": {"params.dest": {"glob": "internet/*"}}},
            # in-boundary reads are fine
            {"id": "allow-in-tenant-read", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*", "params.tenant": "acme"}},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("BOUNDARY INTEGRITY  -  data does not cross unless authorized")

    assert policy.validate() == []
    print(f"\nPolicy '{policy.name}': tenant, classification, and egress boundaries.\n")

    leak = show(policy, {"action": "data.send", "params": {
        "classification": "secret", "dest": "external/partner"}},
        "classified -> external: denied")
    cross = show(policy, {"action": "read.invoices",
                          "params": {"tenant": "globex"}},
                 "cross-tenant read: denied")
    egress = show(policy, {"action": "data.send",
                           "params": {"dest": "internet/webhook"}},
                  "public egress: gated")
    inside = show(policy, {"action": "read.invoices",
                           "params": {"tenant": "acme"}},
                  "own tenant: allowed")

    assert leak.effect is Effect.DENY and leak.doctrine == "S6"
    assert cross.effect is Effect.DENY
    assert egress.effect is Effect.REQUIRE_APPROVAL
    assert inside.effect is Effect.ALLOW

    print("\nEach boundary is checked before the fact. The exfil paths are closed")
    print("by rule, not caught by an alert after the data already left.")


if __name__ == "__main__":
    main()

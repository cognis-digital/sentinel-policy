"""Scenario 2 - security engineers.

Least authority (S2) and gated escalation (S3) are the load-bearing controls
when an agent has real credentials. This demo builds a policy *in code* (same
shape as the JSON, just constructed directly) that confines an agent to one
tenant's read scope, gates anything that touches secrets behind approval, and
denies the classic privilege-bleed move: reading across a tenant boundary. The
verdicts show the blast radius is bounded before the fact, not after.
"""
from _common import banner, show
from sentinel_policy import Effect, Policy


def build_policy() -> Policy:
    return Policy.from_dict({
        "name": "least-authority",
        "default": "deny",            # everything not explicitly allowed is denied
        "rules": [
            {"id": "read-own-tenant", "doctrine": "S2", "effect": "allow",
             "priority": 5,
             "match": {"action": "read.*", "params.tenant": {"eq": "acme"}}},
            {"id": "secrets-need-approval", "doctrine": "S3",
             "effect": "require_approval", "tier": "high", "priority": 20,
             "match": {"params.resource": {"glob": "secret/*"}},
             "reason": "credential access escalates above the routine tier"},
            {"id": "deny-cross-tenant", "doctrine": "S6", "effect": "deny",
             "priority": 10,
             "match": {"action": "read.*", "params.tenant": {"ne": "acme"}},
             "reason": "no reading across a tenant boundary"},
        ],
    })


def main() -> None:
    policy = build_policy()
    banner("LEAST AUTHORITY  -  scope an agent's credentials, gate the secrets")

    assert policy.validate() == [], "policy should be valid"
    print(f"\nPolicy '{policy.name}' built in code and validated clean.")
    print("Agent holds a token scoped to tenant 'acme'. Watch the boundary:\n")

    show(policy, {"action": "read.invoices", "params": {"tenant": "acme"}},
         "in scope")
    secret = show(policy, {"action": "read.config",
                           "params": {"tenant": "acme", "resource": "secret/db-pw"}},
                  "S3 outranks the allow: secrets gate")
    show(policy, {"action": "read.invoices", "params": {"tenant": "globex"}},
         "privilege bleed, refused")
    show(policy, {"action": "write.invoices", "params": {"tenant": "acme"}},
         "writes never granted -> default deny")

    # Priority is the security-critical detail: the high-priority approval gate
    # wins over the lower-priority tenant allow for the same directive.
    assert secret.effect is Effect.REQUIRE_APPROVAL and secret.rule == "secrets-need-approval"

    print("\nSame read action, three different verdicts - because scope, boundary,")
    print("and escalation tier are evaluated, not the verb alone.")


if __name__ == "__main__":
    main()

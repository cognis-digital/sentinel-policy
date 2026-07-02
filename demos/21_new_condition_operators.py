"""Scenario 21 - richer condition operators (regex / cidr / time_window / set).

Least Authority (S2) and Boundary Integrity (S6) get sharper when a policy can
reason about *where* (CIDR), *when* (time window), *shape* (regex), and *scope*
(set membership) — not just literal equality. This demo builds one policy that
uses each new operator and shows it deciding real directives.
"""
from _common import banner
from sentinel_policy import Effect, Policy


def main() -> None:
    banner("RICHER OPERATORS  -  regex / cidr / time_window / subset")

    policy = Policy.from_dict({
        "name": "operator-showcase", "default": "allow",
        "rules": [
            {"id": "block-offhours-deploy", "effect": "deny", "doctrine": "S3",
             "match": {"action": {"regex": r"^deploy(\.|$)"},
                       "params.clock": {"time_window": "18:00-06:00"}},
             "reason": "no deploys outside business hours"},
            {"id": "internal-only-admin", "effect": "deny", "doctrine": "S6",
             "match": {"action": "admin.*",
                       "src.ip": {"not_": {"cidr": "10.0.0.0/8"}}},
             "reason": "admin actions only from the internal network"},
            {"id": "scope-ceiling", "effect": "require_approval", "tier": "high",
             "doctrine": "S2",
             "match": {"scopes": {"superset": ["billing:write"]}},
             "reason": "writing billing scope needs approval"},
        ],
    })
    assert policy.validate() == []

    checks = [
        ({"action": "deploy", "params": {"clock": "23:30"}}, Effect.DENY,
         "deploy at 23:30 -> off-hours"),
        ({"action": "deploy", "params": {"clock": "10:00"}}, Effect.ALLOW,
         "deploy at 10:00 -> business hours"),
        ({"action": "admin.reset", "src": {"ip": "8.8.8.8"}}, Effect.DENY,
         "admin from external IP"),
        ({"action": "admin.reset", "src": {"ip": "10.2.3.4"}}, Effect.ALLOW,
         "admin from internal IP"),
        ({"scopes": ["read", "billing:write"]}, Effect.REQUIRE_APPROVAL,
         "requests billing:write scope"),
    ]
    for directive, expect, note in checks:
        d = policy.evaluate(directive)
        verdict = d.effect.value.upper()
        cite = d.doctrine or "--"
        print(f"  {verdict:<16} [{cite}]  {note}")
        assert d.effect is expect, (directive, d.effect, expect)

    print("\nEach operator is total: a malformed value fails closed, never crashes.")


if __name__ == "__main__":
    main()

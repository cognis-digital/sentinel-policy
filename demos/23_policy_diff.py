"""Scenario 23 - policy diffing: what changed, and does it loosen control?

Before enforcing a new policy version you want to see exactly how it differs
from the one you trust - and, above all, whether the change *loosens* control
(something newly permitted). `diff_policies(old, new)` answers both, as data you
can gate a release on.
"""
from _common import banner
from sentinel_policy import Policy, diff_policies


def main() -> None:
    banner("POLICY DIFF  -  added / removed / changed, with a loosening flag")

    old = Policy.from_dict({
        "name": "prod-controls", "default": "deny",
        "rules": [
            {"id": "reads", "effect": "allow", "doctrine": "S2",
             "match": {"action": "read.*"}},
            {"id": "gate-prod", "effect": "require_approval", "tier": "high",
             "doctrine": "S3", "match": {"params.env": {"eq": "prod"}}},
            {"id": "no-export", "effect": "deny", "doctrine": "S6",
             "match": {"action": "*export*"}},
        ],
    })
    new = Policy.from_dict({
        "name": "prod-controls", "default": "deny",
        "rules": [
            {"id": "reads", "effect": "allow", "doctrine": "S2",
             "match": {"action": "read.*"}},
            # gate-prod downgraded from approval to allow -> LOOSENS
            {"id": "gate-prod", "effect": "allow", "doctrine": "S3",
             "match": {"params.env": {"eq": "prod"}}},
            # no-export removed entirely -> LOOSENS
            {"id": "new-audit", "effect": "require_approval", "tier": "low",
             "doctrine": "S4", "match": {"action": "audit.*"}},
        ],
    })

    d = diff_policies(old, new)
    print()
    print(d.render())

    assert not d.is_empty
    assert d.loosens_control, "this change should be flagged as loosening"
    changed_ids = {c.rule for c in d.changed}
    assert "gate-prod" in changed_ids
    assert any(r.id == "no-export" for r in d.removed)
    assert any(r.id == "new-audit" for r in d.added)

    print("\nA release gate can refuse to ship a diff whose loosens_control is True")
    print("unless a human signs off - that is change control, in code.")


if __name__ == "__main__":
    main()

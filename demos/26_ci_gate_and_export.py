"""Scenario 26 - CI gate + export: fail a bad policy, ship it to OPA / YAML.

`build_report` folds lint + doctrine coverage + shape (+ dead-rule detection)
into one object a CI job can assert on. And because a policy is just data, it can
be exported to YAML (friendlier authoring) or a readable subset of OPA Rego (for
teams standardized on OPA) - with the doctrine citations carried along.
"""
from _common import banner, example_policy
from sentinel_policy import Policy, build_report, from_yaml, to_rego, to_yaml


def main() -> None:
    banner("CI GATE + EXPORT  -  one report to gate on, and portable output")

    policy = example_policy()
    rep = build_report(policy)
    print("\n" + rep.render())

    # a CI gate would fail the build on any of these:
    assert rep.valid, "policy must be well-formed"
    assert not rep.dead_rules, "no unreachable rules"
    MIN_COVERAGE = 40.0
    assert rep.coverage_pct >= MIN_COVERAGE, \
        f"coverage {rep.coverage_pct:.0f}% below floor {MIN_COVERAGE:.0f}%"
    print(f"\n  CI GATE: PASS (valid, no dead rules, coverage "
          f"{rep.coverage_pct:.0f}% >= {MIN_COVERAGE:.0f}%)")

    # a deliberately broken policy fails the same gate
    broken = Policy.from_dict({"name": "broken", "default": "deny", "rules": [
        {"id": "x", "effect": "require_approval", "match": {}},   # no tier
    ]})
    assert not build_report(broken).valid
    print("  CI GATE: correctly FAILS a policy with a tier-less approval rule")

    # export round-trips through YAML with identical semantics
    yaml_text = to_yaml(policy)
    assert from_yaml(yaml_text).to_dict() == policy.to_dict()
    print("\n  YAML export re-imports to an identical policy.")

    # and exports to readable Rego for OPA-native review
    rego = to_rego(policy)
    assert "package sentinel" in rego and "doctrine S" in rego
    print("  Rego export (first lines):\n")
    for line in rego.splitlines()[:8]:
        print("    " + line)

    print("\nSame rules, three surfaces: JSON to enforce, YAML to author, Rego to review.")


if __name__ == "__main__":
    main()

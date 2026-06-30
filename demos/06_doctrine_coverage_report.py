"""Scenario 6 - compliance: machine-checked doctrine coverage.

Demo 3 narrated coverage by hand; this one uses the engine's own
`Policy.doctrine_coverage()` so the report is data, not prose. An auditor can
diff `covered` / `uncovered` between releases and assert the gaps are
*intentional* - which is Provable Refusal (S7) applied to the policy itself.
"""
import json

from _common import banner, example_policy
from sentinel_policy import DOCTRINE


def main() -> None:
    policy = example_policy()
    banner("DOCTRINE COVERAGE REPORT  -  machine-checked, diffable")

    cov = policy.doctrine_coverage()
    print(f"\nPolicy '{policy.name}': {len(policy.rules)} rules\n")
    print("  covered   :", ", ".join(cov["covered"]) or "(none)")
    print("  uncovered :", ", ".join(cov["uncovered"]) or "(none)")
    print(f"  {len(cov['covered'])}/{len(DOCTRINE)} SENTINEL principles enforced\n")

    print("Per-rule citation map:")
    for rid, doc in cov["by_rule"].items():
        print(f"  {rid:<28} -> {doc or '(uncited)'}")

    print("\nThe gaps an auditor should challenge (documented, not hidden):")
    for sid in cov["uncovered"]:
        principle = next(d for d in DOCTRINE if d.id == sid)
        print(f"  [ ] {sid}  {principle.name}")

    print("\nMachine-readable form (commit this; diff it across releases):")
    print("  " + json.dumps(cov, separators=(",", ":")))

    assert set(cov["covered"]) | set(cov["uncovered"]) == {d.id for d in DOCTRINE}
    assert "S2" in cov["covered"]


if __name__ == "__main__":
    main()

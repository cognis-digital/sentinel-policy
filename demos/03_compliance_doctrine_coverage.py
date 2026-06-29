"""Scenario 3 - compliance & audit.

An auditor's first question is not "what does the code do" but "show me the
rules, and show me they map to a principle." The SENTINEL doctrine is published
as data (`DOCTRINE`), and every policy rule cites the doctrine id it serves.
This demo reads the shipped policy back, prints each rule against the doctrine
statement it enforces, and reports which of the seven principles the policy
actually covers - a coverage report you can hand to a reviewer.
"""
from _common import banner, example_policy
from sentinel_policy import DOCTRINE, rule


def main() -> None:
    policy = example_policy()
    banner("DOCTRINE COVERAGE  -  every rule traces to a published principle")

    print(f"\nPolicy '{policy.name}' validates clean: {policy.validate() == []}")
    print("\nEach enforcement rule, and the doctrine principle it cites:\n")

    cited = set()
    for r in policy.rules:
        doc = rule(r.doctrine) if r.doctrine else None
        cited.add(r.doctrine)
        name = doc.name if doc else "(uncited)"
        print(f"  {r.id:<28} -> {r.doctrine or '--'}  {name}")
        if doc:
            print(f"       \"{doc.statement}\"")

    print("\nDoctrine coverage across all seven SENTINEL rules:\n")
    covered = sum(1 for d in DOCTRINE if d.id in cited)
    for d in DOCTRINE:
        mark = "x" if d.id in cited else " "
        print(f"  [{mark}] {d.id}  {d.name}")
    print(f"\n  {covered}/7 principles enforced by this policy; "
          f"the rest are documented gaps an auditor can challenge.")

    # The whole point: no rule can cite a principle that does not exist.
    for r in policy.rules:
        if r.doctrine is not None:
            assert any(d.id == r.doctrine for d in DOCTRINE)

    print("\nThe doctrine is open. Fork it, argue with it, tighten it - but every")
    print("decision your agents make is now traceable to a rule you can read.")


if __name__ == "__main__":
    main()

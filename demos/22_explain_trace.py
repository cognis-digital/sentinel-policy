"""Scenario 22 - explain / dry-run: see *why*, not just the verdict.

Provable Refusal (S7) is stronger when you can show the whole reasoning path.
`Policy.explain(directive)` returns a Trace: every rule considered, in priority
order, whether it matched, and which one decided. Nothing external happens - it
is a dry run you can hand to a reviewer.
"""
from _common import banner, example_policy


def main() -> None:
    policy = example_policy()
    banner("EXPLAIN / DRY-RUN  -  the full reasoning trace for a directive")

    for directive in (
        {"actor": "alice", "action": "read.logs", "params": {}},
        {"actor": "bob", "action": "deploy", "params": {"env": "prod"}},
        {"actor": "carol", "action": "data.export", "params": {}},
        {"actor": "dave", "action": "mystery.op", "params": {}},
    ):
        trace = policy.explain(directive)
        print()
        print(trace.render())
        # every trace names the rule that decided - never a silent outcome
        assert trace.decided_by
        # explain and evaluate always agree on the verdict
        assert trace.decision.effect is policy.evaluate(directive).effect

    print("\nThe trace is data (trace.as_dict()) too - diff it, log it, assert on it.")


if __name__ == "__main__":
    main()

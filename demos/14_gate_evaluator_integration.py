"""Scenario 14 - integration: wiring a policy into a host gate.

`Policy.as_gate_evaluator()` returns a plain callable `directive -> Decision |
None`. This demo simulates the host side (the shape `agentledger`'s PolicyGate
expects) with a tiny in-file gate that records every decision, showing both
modes: `defer_on_default=False` (the policy always decides) and `=True` (the
policy defers on its default so the host's own rule takes over).
"""
from _common import banner
from sentinel_policy import Effect, Policy


POLICY = Policy.from_dict({
    "name": "host-integration", "default": "deny",
    "rules": [
        {"id": "allow-reads", "doctrine": "S2", "effect": "allow",
         "match": {"action": "read.*"}},
        {"id": "gate-deploy", "doctrine": "S3", "effect": "require_approval",
         "tier": "high", "match": {"action": "deploy"}},
    ],
})


class HostGate:
    """Stand-in for a host policy gate: it calls the evaluator and keeps a log."""

    def __init__(self, evaluator, fallback_allow=False):
        self._evaluator = evaluator
        self._fallback_allow = fallback_allow
        self.log = []

    def submit(self, actor, action, params):
        decision = self._evaluator({"actor": actor, "action": action,
                                    "params": params})
        if decision is None:                       # policy deferred
            verdict = "ALLOW(host)" if self._fallback_allow else "DENY(host)"
        else:
            verdict = decision.effect.value
        self.log.append((actor, action, verdict))
        return decision, verdict


def main() -> None:
    banner("GATE EVALUATOR INTEGRATION  -  drop a policy into a host gate")

    print("\n-- mode A: defer_on_default=False (policy always decides) --\n")
    gate_a = HostGate(POLICY.as_gate_evaluator(defer_on_default=False))
    for actor, action in [("alice", "read.logs"), ("bob", "deploy"),
                          ("carol", "delete.everything")]:
        decision, verdict = gate_a.submit(actor, action, {})
        rule = decision.rule if decision else "-"
        print(f"  {actor:<6} {action:<18} -> {verdict:<16} (rule={rule})")

    print("\n-- mode B: defer_on_default=True (host decides the default) --\n")
    gate_b = HostGate(POLICY.as_gate_evaluator(defer_on_default=True),
                      fallback_allow=True)
    for actor, action in [("alice", "read.logs"),
                          ("carol", "delete.everything")]:
        decision, verdict = gate_b.submit(actor, action, {})
        src = "policy" if decision is not None else "host-fallback"
        print(f"  {actor:<6} {action:<18} -> {verdict:<16} ({src})")

    # mode A decides everything; mode B handed the unmatched action to the host
    assert gate_a.log[-1][2] == Effect.DENY.value
    assert gate_b.log[-1][2] == "ALLOW(host)"

    print("\nThe evaluator is just a function, so any host that can call")
    print("`f(directive) -> decision` can enforce a sentinel-policy.")


if __name__ == "__main__":
    main()

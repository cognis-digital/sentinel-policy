"""Scenario 1 - AI-agent builders.

Before your autonomous agent takes an action, run the directive through the
policy gate and respect the verdict. The engine returns one of three effects -
allow, deny, require_approval - and *cites the doctrine rule* that decided. This
demo plays the agent's side of that loop against the shipped prod-controls
policy: routine reads pass, a prod deploy is held for approval, an export is
refused, and an unrecognized action falls to the policy default.
"""
from _common import banner, example_policy, show
from sentinel_policy import Effect


def main() -> None:
    policy = example_policy()
    banner("AGENT BUILDER GATE  -  decide before you act, cite the rule")

    print(f"\nPolicy '{policy.name}' loaded: {len(policy.rules)} rules, "
          f"default={policy.default.value}.")
    print("The agent submits each intended action and obeys the verdict:\n")

    show(policy, {"actor": "ci-bot", "action": "read.metrics", "params": {}},
         "telemetry read, least authority")
    deploy = show(policy, {"actor": "deploy-bot", "action": "deploy",
                           "params": {"env": "prod"}}, "held: needs change-control")
    show(policy, {"actor": "etl-bot", "action": "customer.export", "params": {}},
         "blocked at the boundary")
    show(policy, {"actor": "deploy-bot", "action": "deploy",
                  "params": {"env": "staging"}}, "non-prod is fine")
    show(policy, {"actor": "rogue", "action": "rm.tablespace", "params": {}},
         "unknown -> default")

    # An agent must treat REQUIRE_APPROVAL as "not yet": .allowed is False.
    assert not deploy.allowed and deploy.obligations.get("approval_required") is True
    assert deploy.effect is Effect.REQUIRE_APPROVAL

    print("\nThe agent has a machine-readable verdict for every action, and for")
    print("each one it can name the doctrine rule that governed it.")


if __name__ == "__main__":
    main()

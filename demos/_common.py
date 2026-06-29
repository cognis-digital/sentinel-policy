"""Shared helpers for the demo scenarios.

Every scenario builds its policy from the real, public API
(`sentinel_policy.Policy`, `Effect`, `load_policy`, `DOCTRINE`) — no fabricated
functions, no network, no fake output. The policies below are plain data, the
same shape you would commit to a repo and lint with `sentinel lint`.
"""
from __future__ import annotations

import os
import sys

# allow `python demos/NN_xxx.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_policy import DOCTRINE, Effect, Policy, load_policy, rule  # noqa: E402
from sentinel_policy.policy import PolicyRule  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE_POLICY = os.path.join(REPO_ROOT, "policies", "example.json")


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def example_policy() -> Policy:
    """Load the shipped prod-controls policy from policies/example.json."""
    return load_policy(EXAMPLE_POLICY)


def show(policy: Policy, directive: dict, note: str = "") -> "object":
    """Evaluate one directive and print a single narrated verdict line."""
    d = policy.evaluate(directive)
    verdict = {
        Effect.ALLOW: "ALLOW          ",
        Effect.DENY: "DENY           ",
        Effect.REQUIRE_APPROVAL: "REQUIRE-APPROVAL",
    }[d.effect]
    cited = d.doctrine or "--"
    action = directive.get("action", "")
    params = directive.get("params", {})
    pstr = " ".join(f"{k}={v}" for k, v in params.items())
    tail = f"  ({note})" if note else ""
    print(f"  {verdict}  [{cited}] rule={d.rule:<26} {action} {pstr}{tail}")
    return d

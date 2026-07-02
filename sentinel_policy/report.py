"""A combined lint + coverage + shape report for a policy.

`sentinel report` and `sentinel ci` both build on this. It answers, in one pass:

  * Is the policy well-formed?  (lint problems)
  * Which SENTINEL principles does it enforce, and which are gaps?
  * What is the shape — rule count, effect mix, priority span, operators used?
  * Are there rules that can never fire because a broader earlier rule shadows
    them at the same or higher priority?  (dead-rule detection)

The result is a dataclass so CI can assert on it, plus a human render.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from . import conditions
from .policy import Effect, Policy


def _operators_used(policy: Policy) -> "Dict[str, int]":
    counts: Dict[str, int] = {}
    for r in policy.rules:
        if not isinstance(r.match, dict):
            continue
        for spec in r.match.values():
            if isinstance(spec, dict):
                for op in spec:
                    counts[op] = counts.get(op, 0) + 1
    return counts


def _dead_rules(policy: Policy) -> "List[str]":
    """Rules that an earlier, at-least-as-high-priority rule with an empty match
    (matches everything) makes unreachable. A conservative, no-false-alarm check:
    only an earlier catch-all ({} match) is treated as a definite shadow."""
    dead: List[str] = []
    seen_catch_all = False
    for r in policy.rules:  # already sorted by -priority
        if seen_catch_all:
            dead.append(r.id)
        elif isinstance(r.match, dict) and len(r.match) == 0:
            seen_catch_all = True
    return dead


@dataclass
class Report:
    policy_name: str
    version: int
    rule_count: int
    default: str
    problems: List[str] = field(default_factory=list)
    covered: List[str] = field(default_factory=list)
    uncovered: List[str] = field(default_factory=list)
    uncited_rules: List[str] = field(default_factory=list)
    effect_mix: Dict[str, int] = field(default_factory=dict)
    operators_used: Dict[str, int] = field(default_factory=dict)
    dead_rules: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.problems

    @property
    def coverage_pct(self) -> float:
        total = len(self.covered) + len(self.uncovered)
        return 100.0 * len(self.covered) / total if total else 0.0

    def as_dict(self) -> dict:
        return {
            "policy": self.policy_name, "version": self.version,
            "rule_count": self.rule_count, "default": self.default,
            "valid": self.valid, "problems": self.problems,
            "covered": self.covered, "uncovered": self.uncovered,
            "uncited_rules": self.uncited_rules,
            "coverage_pct": round(self.coverage_pct, 1),
            "effect_mix": self.effect_mix,
            "operators_used": self.operators_used,
            "dead_rules": self.dead_rules,
        }

    def render(self) -> str:
        lines = [f"policy   : {self.policy_name} (v{self.version}), "
                 f"{self.rule_count} rules, default={self.default}",
                 f"valid    : {'yes' if self.valid else 'NO'}"]
        if self.problems:
            for p in self.problems:
                lines.append(f"  - {p}")
        lines.append(f"coverage : {len(self.covered)}/"
                     f"{len(self.covered) + len(self.uncovered)} principles "
                     f"({self.coverage_pct:.0f}%)")
        lines.append(f"  covered  : {', '.join(self.covered) or '(none)'}")
        lines.append(f"  uncovered: {', '.join(self.uncovered) or '(none)'}")
        if self.uncited_rules:
            lines.append(f"  uncited rules: {', '.join(self.uncited_rules)}")
        mix = ", ".join(f"{k}={v}" for k, v in sorted(self.effect_mix.items()))
        lines.append(f"effects  : {mix}")
        if self.operators_used:
            ops = ", ".join(f"{k}={v}" for k, v in sorted(self.operators_used.items()))
            lines.append(f"operators: {ops}")
        if self.dead_rules:
            lines.append(f"DEAD RULES (unreachable): {', '.join(self.dead_rules)}")
        return "\n".join(lines)


def build_report(policy: Policy) -> Report:
    cov = policy.doctrine_coverage()
    mix: Dict[str, int] = {}
    for r in policy.rules:
        mix[r.effect.value] = mix.get(r.effect.value, 0) + 1
    return Report(
        policy_name=policy.name,
        version=policy.version,
        rule_count=len(policy.rules),
        default=policy.default.value,
        problems=policy.validate(),
        covered=cov["covered"],
        uncovered=cov["uncovered"],
        uncited_rules=cov["uncited_rules"],
        effect_mix=mix,
        operators_used=_operators_used(policy),
        dead_rules=_dead_rules(policy),
    )

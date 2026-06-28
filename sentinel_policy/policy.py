"""The policy engine: file-backed rules -> decisions, each citing the doctrine.

A policy is data (JSON). Each rule names the doctrine principle it serves
(`doctrine`), an `effect` (allow / deny / require_approval), and a `match`
condition. On evaluation the first matching rule (by priority, then order)
decides; if none match, the policy's `default` applies.

Decision objects expose `allowed`, `rule`, and `reason`, so a Decision can be
returned straight from agentledger's `PolicyGate.use(...)` hook with no import
between the two packages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional, Tuple

from . import conditions
from .doctrine import _BY_ID


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    rule: str
    doctrine: Optional[str] = None
    reason: str = ""
    obligations: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        # only an explicit ALLOW permits execution; approval must be obtained
        # out of band before a REQUIRE_APPROVAL directive may proceed
        return self.effect is Effect.ALLOW

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "effect": self.effect.value,
            "rule": self.rule,
            "doctrine": self.doctrine,
            "reason": self.reason,
            "obligations": self.obligations,
        }


@dataclass
class PolicyRule:
    id: str
    effect: Effect
    match: dict
    doctrine: Optional[str] = None
    reason: str = ""
    tier: Optional[str] = None
    priority: int = 0

    def decision(self) -> Decision:
        obligations: dict = {}
        if self.effect is Effect.REQUIRE_APPROVAL:
            obligations["approval_required"] = True
            if self.tier:
                obligations["tier"] = self.tier
        return Decision(self.effect, self.id, self.doctrine, self.reason, obligations)


class Policy:
    def __init__(self, name: str, rules: List[PolicyRule],
                 default: Effect = Effect.DENY, version: int = 1):
        self.name = name
        self.version = version
        self.default = default
        # stable sort: higher priority first, then declaration order
        self.rules = sorted(rules, key=lambda r: -r.priority)

    # ---- evaluation ------------------------------------------------------
    def _evaluate(self, directive: dict) -> Tuple[Decision, bool]:
        for r in self.rules:
            if conditions.matches(directive, r.match):
                return r.decision(), True
        default = Decision(self.default, "default",
                           reason=f"default-{self.default.value}")
        return default, False

    def evaluate(self, directive: dict) -> Decision:
        """Return a Decision (an explicit rule, or the policy default)."""
        return self._evaluate(directive)[0]

    def as_gate_evaluator(self, defer_on_default: bool = True) -> Callable[[dict], Optional[Decision]]:
        """An evaluator for agentledger's PolicyGate.use(...).

        With defer_on_default=True, returns None when only the default applied,
        so a host gate's own rules can take over. Otherwise always decides.
        """
        def evaluator(directive: dict) -> Optional[Decision]:
            decision, matched = self._evaluate(directive)
            if not matched and defer_on_default:
                return None
            return decision
        return evaluator

    # ---- (de)serialization ----------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = []
        for i, raw in enumerate(data.get("rules", [])):
            rules.append(PolicyRule(
                id=raw.get("id", f"rule-{i}"),
                effect=Effect(raw["effect"]),
                match=raw.get("match", {}),
                doctrine=raw.get("doctrine"),
                reason=raw.get("reason", ""),
                tier=raw.get("tier"),
                priority=int(raw.get("priority", 0)),
            ))
        return cls(
            name=data.get("name", "unnamed"),
            rules=rules,
            default=Effect(data.get("default", "deny")),
            version=int(data.get("version", 1)),
        )

    def validate(self) -> List[str]:
        """Return a list of problems (empty == valid)."""
        problems: List[str] = []
        seen = set()
        for r in self.rules:
            if r.id in seen:
                problems.append(f"duplicate rule id: {r.id}")
            seen.add(r.id)
            if r.doctrine is not None and r.doctrine not in _BY_ID:
                problems.append(f"rule {r.id}: unknown doctrine reference {r.doctrine!r}")
            try:
                for spec in r.match.values():
                    if isinstance(spec, dict):
                        for op in spec:
                            if op not in conditions.known_operators():
                                problems.append(f"rule {r.id}: unknown operator {op!r}")
            except AttributeError:
                problems.append(f"rule {r.id}: match must be an object")
        return problems


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return Policy.from_dict(json.load(fh))

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


@dataclass(frozen=True)
class TraceStep:
    """One rule considered during ``Policy.explain``."""
    rule: str
    matched: bool
    reached: bool          # False if a prior rule already decided
    doctrine: Optional[str] = None
    effect: Optional[str] = None

    def as_dict(self) -> dict:
        return {"rule": self.rule, "matched": self.matched,
                "reached": self.reached, "doctrine": self.doctrine,
                "effect": self.effect}


@dataclass(frozen=True)
class Trace:
    """The full reasoning path for a single directive (see ``Policy.explain``)."""
    directive: dict
    decision: "Decision"
    decided_by: str        # rule id, or "default"
    steps: "List[TraceStep]"
    matched_by_rule: bool

    def as_dict(self) -> dict:
        return {
            "directive": self.directive,
            "decision": self.decision.as_dict(),
            "decided_by": self.decided_by,
            "matched_by_rule": self.matched_by_rule,
            "steps": [s.as_dict() for s in self.steps],
        }

    def render(self) -> str:
        """A human-readable, multi-line explanation."""
        lines = [f"directive: {self.directive}"]
        for s in self.steps:
            if not s.reached:
                mark = "  (not reached)"
            elif s.matched:
                mark = "  MATCH ->"
            else:
                mark = "  skip"
            cite = f" [{s.doctrine}]" if s.doctrine else ""
            lines.append(f"  {mark:<16} rule={s.rule}{cite} effect={s.effect}")
        d = self.decision
        lines.append(f"verdict: {d.effect.value.upper()} by {self.decided_by}"
                     + (f" [{d.doctrine}]" if d.doctrine else "")
                     + (f" — {d.reason}" if d.reason else ""))
        return "\n".join(lines)


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

    # ---- explain / simulate ---------------------------------------------
    def explain(self, directive: dict) -> "Trace":
        """Evaluate a directive and return a full trace of the reasoning.

        Unlike ``evaluate`` (which returns only the verdict), ``explain`` records
        every rule that was considered, in priority order, whether it matched,
        and which one decided — so an operator can see *why* a directive was
        allowed or refused, not just the outcome. This is the dry-run/simulation
        primitive: nothing external happens, you only inspect the decision path.
        """
        steps: List[TraceStep] = []
        decided_at: Optional[str] = None
        decision: Optional[Decision] = None
        for r in self.rules:
            if decision is not None:
                # already decided; record remaining rules as not-reached
                steps.append(TraceStep(rule=r.id, matched=False, reached=False,
                                       doctrine=r.doctrine, effect=r.effect.value))
                continue
            matched = conditions.matches(directive, r.match)
            steps.append(TraceStep(rule=r.id, matched=matched, reached=True,
                                   doctrine=r.doctrine, effect=r.effect.value))
            if matched:
                decision = r.decision()
                decided_at = r.id
        if decision is None:
            decision = Decision(self.default, "default",
                                reason=f"default-{self.default.value}")
            decided_at = "default"
        return Trace(directive=directive, decision=decision,
                     decided_by=decided_at, steps=steps,
                     matched_by_rule=decided_at != "default")

    def simulate(self, directives: "List[dict]") -> "List[Trace]":
        """Explain a batch of directives — a dry run over a scenario set."""
        return [self.explain(d) for d in directives]

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

    # ---- doctrine coverage ----------------------------------------------
    def doctrine_coverage(self) -> dict:
        """Report which SENTINEL principles this policy actually enforces.

        Returns ``covered`` / ``uncovered`` doctrine-id lists, a ``by_rule`` map,
        and ``uncited_rules`` — so a reviewer can assert the gaps are intentional
        rather than accidental. Machine-checkable, diffable across releases.
        """
        cited = {r.doctrine for r in self.rules if r.doctrine}
        all_ids = set(_BY_ID)
        return {
            "covered": sorted(cited & all_ids),
            "uncovered": sorted(all_ids - cited),
            "by_rule": {r.id: r.doctrine for r in self.rules},
            "uncited_rules": sorted(r.id for r in self.rules if not r.doctrine),
        }

    def validate(self) -> List[str]:
        """Return a list of problems (empty == valid).

        Catches: duplicate rule ids, unknown doctrine references, a non-object
        ``match``, unknown condition operators, collection/range operators with
        the wrong operand shape, an uncompilable ``regex``, and a
        ``require_approval`` rule with no ``tier``.
        """
        problems: List[str] = []
        seen = set()
        known = conditions.known_operators()
        for r in self.rules:
            if r.id in seen:
                problems.append(f"duplicate rule id: {r.id}")
            seen.add(r.id)
            if r.doctrine is not None and r.doctrine not in _BY_ID:
                problems.append(f"rule {r.id}: unknown doctrine reference {r.doctrine!r}")
            if r.effect is Effect.REQUIRE_APPROVAL and not r.tier:
                problems.append(f"rule {r.id}: require_approval rule has no tier")
            if not isinstance(r.match, dict):
                problems.append(f"rule {r.id}: match must be an object")
                continue
            for field_path, spec in r.match.items():
                if not isinstance(spec, dict):
                    continue
                for op, operand in spec.items():
                    if op not in known:
                        problems.append(f"rule {r.id}: unknown operator {op!r}")
                        continue
                    if op in conditions.COLLECTION_OPS and not isinstance(
                            operand, (list, tuple, set, str)):
                        problems.append(
                            f"rule {r.id}: operator {op!r} on {field_path!r} "
                            f"needs a list operand, got {type(operand).__name__}")
                    elif op in conditions.RANGE_OPS and not (
                            isinstance(operand, (list, tuple)) and len(operand) == 2):
                        problems.append(
                            f"rule {r.id}: operator {op!r} on {field_path!r} "
                            f"needs a two-element [lo, hi] operand")
                    elif op == "regex" and conditions._compile(operand) is None:
                        problems.append(
                            f"rule {r.id}: operator 'regex' on {field_path!r} "
                            f"is not a compilable pattern: {operand!r}")
        return problems

    # ---- (re)serialization ----------------------------------------------
    def to_dict(self) -> dict:
        """The canonical dict form (round-trips through ``from_dict``)."""
        rules = []
        for r in self.rules:
            rd: dict = {"id": r.id, "effect": r.effect.value, "match": r.match}
            if r.doctrine is not None:
                rd["doctrine"] = r.doctrine
            if r.reason:
                rd["reason"] = r.reason
            if r.tier is not None:
                rd["tier"] = r.tier
            if r.priority:
                rd["priority"] = r.priority
            rules.append(rd)
        return {"version": self.version, "name": self.name,
                "default": self.default.value, "rules": rules}


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return Policy.from_dict(json.load(fh))

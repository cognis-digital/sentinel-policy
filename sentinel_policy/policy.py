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


class PolicyError(ValueError):
    """A policy file (or dict) is malformed.

    Raised by ``Policy.from_dict`` / ``load_policy`` with a message that names
    the offending rule and field, so an operator can fix the JSON without
    reading a traceback. Subclasses ``ValueError`` so existing ``except
    ValueError`` handlers keep working (public API stays stable).
    """


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


def _coerce_effect(value: Any, *, where: str) -> Effect:
    """Turn a raw string into an Effect, with a clear error listing the valid
    values, instead of the bare ``'whoops' is not a valid Effect``."""
    if isinstance(value, Effect):
        return value
    try:
        return Effect(value)
    except ValueError:
        valid = ", ".join(e.value for e in Effect)
        raise PolicyError(
            f"{where}: invalid effect {value!r}; expected one of: {valid}"
        ) from None


def _coerce_int(value: Any, *, where: str, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise PolicyError(f"{where}: expected an integer, got {value!r}") from None


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

    # ---- doctrine coverage ----------------------------------------------
    def doctrine_coverage(self) -> dict:
        """Report which SENTINEL principles this policy actually enforces.

        Returns a dict with:
          ``covered``   - sorted list of doctrine ids cited by at least one rule
          ``uncovered`` - sorted list of doctrine ids no rule cites (the gaps)
          ``by_rule``   - {rule_id: doctrine_id_or_None}
          ``uncited_rules`` - rule ids that cite no doctrine at all

        This makes "Provable Refusal (S7)" auditable for the *policy itself*: a
        reviewer can assert the gaps are intentional rather than accidental.
        """
        cited = {r.doctrine for r in self.rules if r.doctrine}
        all_ids = set(_BY_ID)
        return {
            "covered": sorted(cited & all_ids),
            "uncovered": sorted(all_ids - cited),
            "by_rule": {r.id: r.doctrine for r in self.rules},
            "uncited_rules": sorted(r.id for r in self.rules if not r.doctrine),
        }

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
        if not isinstance(data, dict):
            raise PolicyError(
                f"policy must be a JSON object, got {type(data).__name__}")

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise PolicyError("policy 'rules' must be a list")

        rules = []
        for i, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise PolicyError(f"rule #{i} must be an object, got "
                                  f"{type(raw).__name__}")
            rid = raw.get("id", f"rule-{i}")
            where = f"rule {rid!r}"
            if "effect" not in raw:
                raise PolicyError(f"{where}: missing required field 'effect'")
            match = raw.get("match", {})
            if not isinstance(match, dict):
                raise PolicyError(f"{where}: 'match' must be an object, got "
                                  f"{type(match).__name__}")
            rules.append(PolicyRule(
                id=rid,
                effect=_coerce_effect(raw["effect"], where=where),
                match=match,
                doctrine=raw.get("doctrine"),
                reason=raw.get("reason", ""),
                tier=raw.get("tier"),
                priority=_coerce_int(raw.get("priority"), where=f"{where} priority",
                                     default=0),
            ))
        return cls(
            name=data.get("name", "unnamed"),
            rules=rules,
            default=_coerce_effect(data.get("default", "deny"), where="policy default"),
            version=_coerce_int(data.get("version"), where="policy version", default=1),
        )

    # operators whose operand must be a collection to ever match
    _COLLECTION_OPS = frozenset({"in", "nin"})

    def validate(self) -> List[str]:
        """Return a list of problems (empty == valid).

        Flags: duplicate rule ids, unknown doctrine references, a non-object
        ``match``, unknown condition operators, and operands that can never
        match (e.g. ``in`` against a non-collection, or a ``require_approval``
        rule with no ``tier``).
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
                    elif op in self._COLLECTION_OPS and not isinstance(
                            operand, (list, tuple, set, str)):
                        problems.append(
                            f"rule {r.id}: operator {op!r} on {field_path!r} "
                            f"needs a list operand, got {type(operand).__name__}")
        return problems


def load_policy(path: str) -> Policy:
    """Read a JSON policy from disk.

    Raises ``FileNotFoundError`` if the path does not exist and ``PolicyError``
    (with a message naming the file and the JSON position) if the file is not
    valid JSON or not a valid policy.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"policy file not found: {path}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"{path}: invalid JSON at line {exc.lineno} column {exc.colno}: "
            f"{exc.msg}"
        ) from None
    return Policy.from_dict(data)

"""Policy diffing — what changed between two versions of a policy.

Governance rules drift. Before you enforce a new policy you want to see exactly
how it differs from the one you trust: which rules were added or removed, which
had their effect, doctrine, match, tier, or priority changed, and — most
importantly — which changes *loosen* control (a deny that became an allow, an
approval gate that was dropped). Those are flagged so a reviewer's eye goes
straight to them.

The diff is computed from the policies' declared rules by id, so it is stable
regardless of file formatting, and it is pure data (a ``PolicyDiff``) that you
can render, serialize, or assert on in CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .policy import Effect, Policy, PolicyRule

# effects ordered from most permissive to most restrictive; a move toward a
# lower rank (more permissive) is a loosening of control.
_STRICTNESS = {Effect.ALLOW: 0, Effect.REQUIRE_APPROVAL: 1, Effect.DENY: 2}


@dataclass(frozen=True)
class FieldChange:
    field: str
    old: object
    new: object

    def as_dict(self) -> dict:
        return {"field": self.field, "old": self.old, "new": self.new}


@dataclass(frozen=True)
class RuleChange:
    rule: str
    changes: List[FieldChange]
    loosens: bool          # does any change make the rule more permissive?

    def as_dict(self) -> dict:
        return {"rule": self.rule, "loosens": self.loosens,
                "changes": [c.as_dict() for c in self.changes]}


@dataclass
class PolicyDiff:
    added: List[PolicyRule] = field(default_factory=list)
    removed: List[PolicyRule] = field(default_factory=list)
    changed: List[RuleChange] = field(default_factory=list)
    default_change: Optional[FieldChange] = None

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed or self.default_change)

    @property
    def loosens_control(self) -> bool:
        """True if any change could permit something previously restricted.

        Adding a rule can loosen (a new allow), removing a deny/approval rule
        loosens, a changed rule that moves toward allow loosens, and a default
        that moves toward allow loosens. This is the CI-gate signal.
        """
        if any(r.effect is not Effect.DENY for r in self.added):
            return True
        if any(r.effect is not Effect.ALLOW for r in self.removed):
            return True
        if any(c.loosens for c in self.changed):
            return True
        if self.default_change is not None:
            old, new = self.default_change.old, self.default_change.new
            if _STRICTNESS.get(Effect(new), 0) < _STRICTNESS.get(Effect(old), 0):
                return True
        return False

    def as_dict(self) -> dict:
        return {
            "added": [_rule_summary(r) for r in self.added],
            "removed": [_rule_summary(r) for r in self.removed],
            "changed": [c.as_dict() for c in self.changed],
            "default_change": self.default_change.as_dict() if self.default_change else None,
            "loosens_control": self.loosens_control,
        }

    def render(self) -> str:
        if self.is_empty:
            return "policies are identical (by rule id, effect, match, and default)"
        lines: List[str] = []
        for r in self.added:
            lines.append(f"  + {r.id}  (effect={r.effect.value})")
        for r in self.removed:
            lines.append(f"  - {r.id}  (was effect={r.effect.value})")
        for c in self.changed:
            flag = "  ! " if c.loosens else "  ~ "
            detail = ", ".join(f"{ch.field}: {ch.old!r} -> {ch.new!r}" for ch in c.changes)
            lines.append(f"{flag}{c.rule}  ({detail})")
        if self.default_change:
            dc = self.default_change
            lines.append(f"  * default: {dc.old!r} -> {dc.new!r}")
        if self.loosens_control:
            lines.append("\n  WARNING: this diff LOOSENS control (something newly permitted).")
        return "\n".join(lines)


def _rule_summary(r: PolicyRule) -> dict:
    return {"id": r.id, "effect": r.effect.value, "doctrine": r.doctrine,
            "tier": r.tier, "priority": r.priority}


def _index(policy: Policy) -> "Dict[str, PolicyRule]":
    return {r.id: r for r in policy.rules}


def diff_policies(old: Policy, new: Policy) -> PolicyDiff:
    """Structured diff of two policies, keyed by rule id."""
    old_idx, new_idx = _index(old), _index(new)
    diff = PolicyDiff()

    for rid in new_idx:
        if rid not in old_idx:
            diff.added.append(new_idx[rid])
    for rid in old_idx:
        if rid not in new_idx:
            diff.removed.append(old_idx[rid])

    for rid in old_idx:
        if rid not in new_idx:
            continue
        o, n = old_idx[rid], new_idx[rid]
        changes: List[FieldChange] = []
        if o.effect is not n.effect:
            changes.append(FieldChange("effect", o.effect.value, n.effect.value))
        if o.doctrine != n.doctrine:
            changes.append(FieldChange("doctrine", o.doctrine, n.doctrine))
        if o.match != n.match:
            changes.append(FieldChange("match", o.match, n.match))
        if o.tier != n.tier:
            changes.append(FieldChange("tier", o.tier, n.tier))
        if o.priority != n.priority:
            changes.append(FieldChange("priority", o.priority, n.priority))
        if o.reason != n.reason:
            changes.append(FieldChange("reason", o.reason, n.reason))
        if changes:
            loosens = (o.effect is not n.effect and
                       _STRICTNESS[n.effect] < _STRICTNESS[o.effect])
            diff.changed.append(RuleChange(rid, changes, loosens))

    if old.default is not new.default:
        diff.default_change = FieldChange("default", old.default.value, new.default.value)

    return diff

"""The SENTINEL doctrine — seven rules for governing autonomous agents.

These are original, deliberately concrete, and meant to be argued with. Each
policy rule you write cites the doctrine rule it enforces, so a reviewer can
trace any decision back to a principle rather than a vibe.

SENTINEL is a mnemonic for the through-line: a sentinel stands at a boundary,
checks authority, and keeps a record.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    statement: str
    rationale: str

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "statement": self.statement, "rationale": self.rationale}


def rule(rule_id: str) -> Rule:
    """Look up a doctrine rule by id (e.g. 'S3'). Raises KeyError if unknown."""
    return _BY_ID[rule_id]


DOCTRINE: tuple[Rule, ...] = (
    Rule(
        "S1", "Attributed Intent",
        "Every action traces to a named, authenticated operator and an explicit directive.",
        "If no one authorized it, no one is accountable for it. Anonymous or implicit "
        "authority is the root of the 'who told the agent to do that?' problem.",
    ),
    Rule(
        "S2", "Least Authority",
        "An agent acts within the narrowest scope of data, actions, and environment that "
        "satisfies the directive; everything outside that scope is denied by default.",
        "Blast radius is bounded before the fact, not apologized for after it.",
    ),
    Rule(
        "S3", "Gated Escalation",
        "Any action above a defined risk tier requires a separate, independently authorized "
        "approval before it executes.",
        "High-consequence actions should never ride in on the same authority as routine ones.",
    ),
    Rule(
        "S4", "Immutable Record",
        "Every directive, decision, and outcome is committed to a tamper-evident record "
        "before its effect becomes externally visible.",
        "Evidence written after the fact, or rewritable later, is not evidence.",
    ),
    Rule(
        "S5", "Reversibility Preference",
        "Prefer reversible actions. An irreversible action requires explicit acknowledgement "
        "of its irreversibility and a higher approval tier.",
        "Most mistakes are survivable if they can be undone; the dangerous ones can't.",
    ),
    Rule(
        "S6", "Boundary Integrity",
        "Data and credentials do not cross a classification, tenant, or network boundary "
        "unless the directive explicitly authorizes that crossing.",
        "Exfiltration and privilege bleed almost always look like an un-checked boundary cross.",
    ),
    Rule(
        "S7", "Provable Refusal",
        "A denied or aborted action is recorded with the rule and reason for the refusal. "
        "Silence is not a valid outcome.",
        "A governance system you can't see refusing is one you can't trust to refuse.",
    ),
)

_BY_ID = {r.id: r for r in DOCTRINE}

# fail fast if the doctrine is ever edited into an inconsistent state
assert len(_BY_ID) == len(DOCTRINE) == 7, "SENTINEL doctrine must have 7 unique rules"

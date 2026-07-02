"""Decision-audit log — write every decision as JSONL, replay it later.

Provable Refusal (S7) and Immutable Record (S4) both require that a decision be
a durable, structured record, not a log line you have to regex. This module
turns a `Decision` (plus the directive that produced it) into a canonical JSON
object, appends it one-per-line to a file or stream, and reads the log back into
an aggregate an auditor can act on.

The record is intentionally flat and stable so downstream pipelines (Splunk,
Elastic, agentledger) can ingest it without a schema negotiation. Writing is
append-only; the log is the evidence.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional, TextIO

from .policy import Decision, Policy


def record(directive: dict, decision: Decision,
           *, at: "Optional[str]" = None) -> dict:
    """Build the canonical audit record for one decision."""
    ts = at or datetime.now(timezone.utc).isoformat()
    return {
        "ts": ts,
        "actor": directive.get("actor"),
        "action": directive.get("action"),
        "params": directive.get("params", {}),
        "allowed": decision.allowed,
        "effect": decision.effect.value,
        "rule": decision.rule,
        "doctrine": decision.doctrine,
        "reason": decision.reason,
        "obligations": decision.obligations,
    }


def to_jsonl(records: "Iterable[dict]") -> str:
    """Serialize records to a JSONL string (one compact object per line)."""
    return "\n".join(json.dumps(r, separators=(",", ":"), sort_keys=True)
                     for r in records)


class AuditLog:
    """Append-only JSONL decision log.

    Use as a context manager to write to a file:

        with AuditLog("decisions.jsonl") as log:
            log.write(directive, policy.evaluate(directive))

    or hand it an open stream (e.g. ``sys.stdout``) for piping.
    """

    def __init__(self, path_or_stream, *, clock=None) -> None:
        self._own = isinstance(path_or_stream, str)
        self._target = path_or_stream
        self._fh: "Optional[TextIO]" = None
        self._clock = clock  # callable -> iso string, for deterministic tests
        self.count = 0

    def __enter__(self) -> "AuditLog":
        if self._own:
            self._fh = open(self._target, "a", encoding="utf-8")
        else:
            self._fh = self._target
        return self

    def __exit__(self, *exc) -> None:
        if self._own and self._fh is not None:
            self._fh.close()
        self._fh = None

    def write(self, directive: dict, decision: Decision) -> dict:
        if self._fh is None:
            raise RuntimeError("AuditLog must be used as a context manager")
        rec = record(directive, decision,
                     at=self._clock() if self._clock else None)
        self._fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        self.count += 1
        return rec

    def write_many(self, policy: Policy, directives: "Iterable[dict]") -> "List[dict]":
        return [self.write(d, policy.evaluate(d)) for d in directives]


@dataclass
class ReplaySummary:
    total: int = 0
    by_effect: Counter = field(default_factory=Counter)
    by_doctrine: Counter = field(default_factory=Counter)
    by_rule: Counter = field(default_factory=Counter)
    by_actor: Counter = field(default_factory=Counter)
    denied: List[dict] = field(default_factory=list)      # deny records
    approvals: List[dict] = field(default_factory=list)   # require_approval records
    unlabeled: List[dict] = field(default_factory=list)   # records missing a rule id

    @property
    def refusals(self) -> int:
        return self.by_effect.get("deny", 0)

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "by_effect": dict(self.by_effect),
            "by_doctrine": dict(self.by_doctrine),
            "by_rule": dict(self.by_rule),
            "by_actor": dict(self.by_actor),
            "refusals": self.refusals,
            "approvals_held": len(self.approvals),
            "unlabeled": len(self.unlabeled),
        }

    def render(self) -> str:
        lines = [f"records: {self.total}"]
        for eff, n in sorted(self.by_effect.items()):
            lines.append(f"  {eff:<18}: {n}")
        if self.by_doctrine:
            lines.append("  doctrine invoked: " +
                         ", ".join(f"{k}x{v}" for k, v in sorted(self.by_doctrine.items())))
        if self.unlabeled:
            lines.append(f"  WARNING: {len(self.unlabeled)} record(s) had no rule id "
                         "(a silent outcome — violates S7)")
        return "\n".join(lines)


def replay(lines: "Iterable[str]") -> ReplaySummary:
    """Aggregate a JSONL decision log back into an auditable summary."""
    s = ReplaySummary()
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        s.total += 1
        eff = rec.get("effect", "?")
        s.by_effect[eff] += 1
        if rec.get("doctrine"):
            s.by_doctrine[rec["doctrine"]] += 1
        if rec.get("actor"):
            s.by_actor[rec["actor"]] += 1
        rule = rec.get("rule")
        if rule:
            s.by_rule[rule] += 1
        else:
            s.unlabeled.append(rec)
        if eff == "deny":
            s.denied.append(rec)
        elif eff == "require_approval":
            s.approvals.append(rec)
    return s


def replay_file(path: str) -> ReplaySummary:
    if not os.path.exists(path):
        raise FileNotFoundError(f"audit log not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return replay(fh)

"""sentinel-policy — an open governance doctrine and a policy-gate engine for AI agents.

Two things ship here:

  1. The SENTINEL doctrine: seven plainly-stated rules for governing what an
     autonomous agent is allowed to do in a high-stakes environment.

  2. A reference engine that turns a file-backed policy into allow / deny /
     require-approval decisions, each tagged with the doctrine rule it serves.
     The engine is decision-only and dependency-free, and its Decision objects
     are drop-in for agentledger's policy-gate hook.

Beyond the core (stable), this package also exposes:
  * explain/simulate  — dry-run a directive and inspect the full reasoning trace
  * diff_policies     — structured diff of two policy versions (flags loosening)
  * AuditLog / replay — JSONL decision log + replay/aggregate
  * build_report      — combined lint + coverage + shape report
  * RateLimiter       — sliding-window rate guard for decisions
  * YAML / Rego I/O   — import/export a policy to other formats
"""

from .audit import AuditLog, ReplaySummary, record, replay, replay_file, to_jsonl
from .diffing import PolicyDiff, RuleChange, diff_policies
from .doctrine import DOCTRINE, Rule, rule
from .policy import Decision, Effect, Policy, Trace, TraceStep, load_policy
from .ratelimit import InMemoryStore, RateLimiter, RateVerdict, key_from_directive
from .report import Report, build_report
from .serialization import from_yaml, to_rego, to_yaml

__version__ = "0.2.0"
__all__ = [
    # core (stable)
    "DOCTRINE", "Rule", "rule",
    "Policy", "Decision", "Effect", "load_policy",
    # explain / simulate
    "Trace", "TraceStep",
    # diffing
    "diff_policies", "PolicyDiff", "RuleChange",
    # audit
    "AuditLog", "ReplaySummary", "record", "replay", "replay_file", "to_jsonl",
    # report
    "Report", "build_report",
    # rate limiting
    "RateLimiter", "RateVerdict", "InMemoryStore", "key_from_directive",
    # serialization
    "to_yaml", "from_yaml", "to_rego",
    "__version__",
]

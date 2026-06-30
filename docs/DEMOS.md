# Demos

Twenty runnable scenarios in [`../demos/`](../demos/), each targeting a real
audience or behavior. Every scenario uses only the real public API
(`Policy`, `Effect`, `Decision`, `PolicyError`, `load_policy`, `DOCTRINE`,
`rule`), needs no network, prints narrated output, and exits 0 — so they double
as smoke tests (`tests/test_demos.py` runs every one under `pytest`).

```bash
# Windows console is cp1252; force UTF-8 so the output renders cleanly.
PYTHONUTF8=1 python demos/run_all.py            # all twenty, end to end
PYTHONUTF8=1 python demos/09_priority_conflict_resolution.py   # or just one
```

| # | Demo | Audience | What it shows |
|---|------|----------|----------------|
| 1 | [`01_agent_builder_gate.py`](../demos/01_agent_builder_gate.py) | AI-agent builders | Run each intended action through the gate and obey the verdict — allow / deny / require-approval, each citing its doctrine rule. |
| 2 | [`02_security_least_authority.py`](../demos/02_security_least_authority.py) | Security engineers | Confine an agent to one tenant's read scope, gate secrets behind approval (priority), and deny the cross-tenant privilege bleed. |
| 3 | [`03_compliance_doctrine_coverage.py`](../demos/03_compliance_doctrine_coverage.py) | Compliance & audit | Map every policy rule to the SENTINEL principle it cites and report doctrine coverage by hand — a report you can hand a reviewer. |
| 4 | [`04_platform_layered_policies.py`](../demos/04_platform_layered_policies.py) | Platform engineers | Layer an org-wide doctrine above a permissive team policy using `as_gate_evaluator(defer_on_default=True)`. |
| 5 | [`05_provable_refusal_log.py`](../demos/05_provable_refusal_log.py) | Safety / SRE on call | Provable Refusal (S7): serialize a `Decision` for every directive into an audit-shaped log — no silent denials. |
| 6 | [`06_doctrine_coverage_report.py`](../demos/06_doctrine_coverage_report.py) | Compliance & audit | The engine's own `Policy.doctrine_coverage()` — machine-checked, diffable `covered` / `uncovered` you can assert across releases. |
| 7 | [`07_lint_catches_mistakes.py`](../demos/07_lint_catches_mistakes.py) | Platform engineers | `validate()` reports every problem at once (unknown doctrine, bad operator, missing tier, duplicate id) so CI fails a bad policy. |
| 8 | [`08_malformed_policy_errors.py`](../demos/08_malformed_policy_errors.py) | Platform engineers | Malformed input raises a `PolicyError` that names the offending rule/field — a fix-it message, not a traceback. |
| 9 | [`09_priority_conflict_resolution.py`](../demos/09_priority_conflict_resolution.py) | Security engineers | When a broad allow and a narrow deny overlap, the higher-priority targeted rule wins — deterministically. |
| 10 | [`10_reversibility_gate.py`](../demos/10_reversibility_gate.py) | Safety | Reversibility Preference (S5): the `irreversible` flag, not the verb, decides the tier; one-way actions always gate. |
| 11 | [`11_numeric_thresholds.py`](../demos/11_numeric_thresholds.py) | Finance / ops | `gt`/`ge`/`lt`/`le` gate by magnitude (spend tiers); a non-numeric amount fails safe to the default instead of slipping through. |
| 12 | [`12_attributed_intent.py`](../demos/12_attributed_intent.py) | Governance | Attributed Intent (S1): unattributed/`unknown` actors are denied up front; attribution is the floor, not the ceiling. |
| 13 | [`13_boundary_integrity.py`](../demos/13_boundary_integrity.py) | Security engineers | Boundary Integrity (S6): tenant, classification, and network-egress boundaries each closed by rule, before the fact. |
| 14 | [`14_gate_evaluator_integration.py`](../demos/14_gate_evaluator_integration.py) | Integrators | Wire `as_gate_evaluator()` into a host gate; both `defer_on_default` modes, with a tiny in-file gate that logs every decision. |
| 15 | [`15_three_tier_stack.py`](../demos/15_three_tier_stack.py) | Platform engineers | A three-tier doctrine → org → team stack composed purely by deferral — the non-negotiable doctrine on top. |
| 16 | [`16_load_lint_from_disk.py`](../demos/16_load_lint_from_disk.py) | Ops | Author → write → `load_policy` → lint → eval round-trip, then a corrupted file rejected cleanly at load time. |
| 17 | [`17_default_policy_modes.py`](../demos/17_default_policy_modes.py) | Governance | The same unmatched directive under `deny` / `require_approval` / `allow` defaults — the posture is one deliberate line. |
| 18 | [`18_audit_log_jsonl.py`](../demos/18_audit_log_jsonl.py) | Audit | Emit a JSONL decision log, then replay it to count effects and doctrine rules invoked — the evidence and the summary. |
| 19 | [`19_doctrine_walkthrough.py`](../demos/19_doctrine_walkthrough.py) | Onboarding | Each of the seven rules paired with the one-line policy snippet that enforces it; the snippets compose into a 7/7-coverage policy. |
| 20 | [`20_cli_walkthrough.py`](../demos/20_cli_walkthrough.py) | Everyone | Every CLI subcommand (`doctrine` / `lint` / `coverage` / `eval`) driven in-process, asserting real exit codes. |

## 1. Agent builder gate — *decide before you act, cite the rule*
**Audience:** teams building autonomous AI agents.
The agent submits each intended action to the shipped `prod-controls` policy and
respects the verdict: routine reads pass (S2), a prod deploy is held for
approval (S3), an export is refused at the boundary (S6), and an unrecognized
action falls to the policy default. `REQUIRE_APPROVAL` is treated as "not yet" —
`.allowed` is `False` and `obligations.approval_required` is `True`.

## 2. Least authority — *scope the credentials, gate the secrets*
**Audience:** security engineers.
A policy built in code confines an agent to tenant `acme`'s reads, gates any
`secret/*` resource behind a higher-tier approval, and denies reads of another
tenant. The same `read.*` verb yields three different verdicts because scope,
boundary, and escalation tier are evaluated — and rule **priority** lets the
approval gate outrank the broad allow.

## 3. Doctrine coverage — *every rule traces to a published principle*
**Audience:** compliance and audit.
Reads the shipped policy back, prints each rule against the doctrine statement
it enforces, and reports which of the seven SENTINEL principles the policy
covers — with the gaps shown explicitly so an auditor can challenge them. No
rule can cite a principle that does not exist.

## 4. Layered policies — *an org doctrine above team policies*
**Audience:** platform engineers.
A permissive team policy defers on its default (`defer_on_default=True`) so a
strict org policy governs everything the team left open: the org gates
irreversible actions (S5) and denies cross-boundary export (S6). Composition is
just function layering — no DSL, no daemon.

## 5. Provable refusal — *no silent denials, everything is a record*
**Audience:** safety engineers and SREs on call.
Runs a batch of directives through the policy and emits a structured,
audit-shaped record for each via `Decision.as_dict()`, then summarizes how many
were allowed, gated, or refused. Every action — allowed or refused — leaves a
record naming the rule that decided it.

## 6. Doctrine coverage report — *machine-checked, diffable*
**Audience:** compliance and audit.
Where demo 3 narrates coverage by hand, this one calls the engine's own
`Policy.doctrine_coverage()` and emits the `covered` / `uncovered` / `by_rule`
report as data. Commit the JSON and diff it across releases to prove the gaps
stayed intentional — Provable Refusal (S7) applied to the policy itself.

## 7. Lint catches mistakes — *fail the bad policy in CI*
**Audience:** platform engineers.
Builds a deliberately broken policy (unknown doctrine, typo'd operator, an `in`
against a non-list, a `require_approval` with no tier, a duplicate id) and prints
every problem `validate()` finds at once, then shows the corrected policy
validating clean. The linter reports, it never executes the policy.

## 8. Malformed policy errors — *fail loud, name the field*
**Audience:** platform engineers.
Feeds several malformed inputs to `Policy.from_dict` and shows each raising a
`PolicyError` whose message names the offending rule and field — a fix-it
message, not a traceback. `PolicyError` subclasses `ValueError`, so existing
handlers keep working.

## 9. Priority conflict resolution — *the targeted rule wins*
**Audience:** security engineers.
A broad `read.*` allow overlaps a high-priority deny on `read.secrets` and a
high-priority bulk-read gate. The same verb yields three verdicts, decided by
priority and the exact match — not by the order the rules were typed.

## 10. Reversibility gate — *undo-able passes, irreversible waits*
**Audience:** safety.
Reversibility Preference (S5): a high-priority rule gates anything flagged
`irreversible`, regardless of verb, so a one-way action can never ride in on
routine authority.

## 11. Numeric thresholds — *gate by magnitude, not just verb*
**Audience:** finance / ops.
Spend under \$1k auto-approves, \$1k–\$100k gates, over \$100k is denied. A
non-numeric amount makes the comparison fail safe (False), so it falls to the
policy default instead of slipping through.

## 12. Attributed intent — *no name, no action*
**Audience:** governance.
Attributed Intent (S1): a directive with no `actor` (or the placeholder
`unknown`) is denied up front. A named operator may do routine reads but risky
work still gates — attribution is necessary, not sufficient.

## 13. Boundary integrity — *data does not cross unless authorized*
**Audience:** security engineers.
Boundary Integrity (S6) across three boundaries — tenant, data classification,
and network egress — each illegitimate crossing denied by rule while the
in-boundary equivalents pass.

## 14. Gate evaluator integration — *drop a policy into a host gate*
**Audience:** integrators.
Drives `as_gate_evaluator()` from a tiny in-file `HostGate` (the shape
`agentledger`'s `PolicyGate` expects), showing both `defer_on_default=False`
(policy always decides) and `=True` (policy defers so the host decides the
default).

## 15. Three-tier stack — *doctrine → org → team*
**Audience:** platform engineers.
Composes a global doctrine overlay (hard, non-negotiable), an org policy, and a
permissive team policy by deferral. The doctrine overlay wins even inside the
team's own namespace; teams stay autonomous below it.

## 16. Load & lint from disk — *the file is the source of truth*
**Audience:** ops.
Writes a policy to a temp file, loads it with `load_policy`, lints and evaluates
it, then writes a broken version and shows `load_policy` raising a clear
`PolicyError` at load time. Cleans up after itself; no fixtures, no network.

## 17. Default policy modes — *the posture is one line*
**Audience:** governance.
The same unmatched directive run against three policies differing only in their
`default` (`deny` / `require_approval` / `allow`). "Deny by default" is least
authority (S2); choosing `allow` should be a visible, signed-off decision.

## 18. Audit log (JSONL) — *every decision is a replayable record*
**Audience:** audit.
Evaluates a batch into a JSONL decision log (one object per line — the format
log pipelines ingest), then replays the log to count effects and the doctrine
rules invoked. The log is the evidence; the summary is what you hand the auditor.

## 19. Doctrine walkthrough — *each rule, with the snippet that enforces it*
**Audience:** onboarding.
Prints each SENTINEL rule from the published `DOCTRINE` data beside a one-line
policy snippet that enforces it. The seven snippets compose into one valid
policy that covers all 7/7 principles — the prose can't drift from the rules.

## 20. CLI walkthrough — *every subcommand, real exit codes*
**Audience:** everyone.
Drives the real CLI entrypoint (`sentinel_policy.cli.main`) for `doctrine`,
`lint`, `coverage`, and `eval`, asserting the exit code each returns (`eval`
returns 0 for allow, 2 for deny/require-approval, so it scripts in a pipeline).

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/` covers the same code paths under `pytest`.

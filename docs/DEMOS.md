# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario uses only the real public API
(`Policy`, `Effect`, `Decision`, `load_policy`, `DOCTRINE`, `rule`), needs no
network, prints narrated output, and exits 0 — so they double as smoke tests
(`tests/test_demos.py` runs every one under `pytest`).

```bash
# Windows console is cp1252; force UTF-8 so the output renders cleanly.
PYTHONUTF8=1 python demos/run_all.py            # all five, end to end
PYTHONUTF8=1 python demos/02_security_least_authority.py   # or just one
```

| # | Demo | Audience | What it shows |
|---|------|----------|----------------|
| 1 | [`01_agent_builder_gate.py`](../demos/01_agent_builder_gate.py) | AI-agent builders | Run each intended action through the gate and obey the verdict — allow / deny / require-approval, each citing its doctrine rule. |
| 2 | [`02_security_least_authority.py`](../demos/02_security_least_authority.py) | Security engineers | Confine an agent to one tenant's read scope, gate secrets behind approval (priority), and deny the cross-tenant privilege bleed. |
| 3 | [`03_compliance_doctrine_coverage.py`](../demos/03_compliance_doctrine_coverage.py) | Compliance & audit | Map every policy rule to the SENTINEL principle it cites and report doctrine coverage (4/7) — a report you can hand a reviewer. |
| 4 | [`04_platform_layered_policies.py`](../demos/04_platform_layered_policies.py) | Platform engineers | Layer an org-wide doctrine above a permissive team policy using `as_gate_evaluator(defer_on_default=True)`. |
| 5 | [`05_provable_refusal_log.py`](../demos/05_provable_refusal_log.py) | Safety / SRE on call | Provable Refusal (S7): serialize a `Decision` for every directive into an audit-shaped log — no silent denials. |

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

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/` covers the same code paths under `pytest`.

# Architecture

`sentinel-policy` is two things that fit together: an **open doctrine** (the
SENTINEL seven rules, published as data) and a **decision-only policy engine**
that turns a file-backed policy into `allow` / `deny` / `require_approval`
verdicts — each verdict citing the doctrine rule it serves. There is no DSL, no
`eval`, no daemon, and no runtime dependency: a policy is plain JSON, and
evaluating it is a pure function.

## The evaluate → verdict flow

```mermaid
flowchart LR
    dir[Directive<br/>actor + action + params] --> ev[Policy.evaluate]
    pol[(Policy file<br/>JSON, sorted by priority)] --> ev
    doc[[SENTINEL doctrine<br/>S1..S7]] -. cited by .-> ev
    ev --> m{first rule<br/>whose match holds?}
    m -- yes --> rd[rule.decision]
    m -- no --> df[policy default]
    rd --> dec[Decision<br/>effect · rule · doctrine · reason · obligations]
    df --> dec
    dec --> a{effect}
    a -- allow --> go[action proceeds]
    a -- deny --> stop[refused, recorded]
    a -- require_approval --> gate[held for out-of-band approval]
    classDef hot stroke:#f4b400,stroke-width:3px;
    class ev,dec hot;
```

A directive is a dict (`actor`, `action`, `params`). The engine walks the
rules — already sorted by descending priority, ties broken by declaration order
— and the **first rule whose `match` condition holds** decides. If none match,
the policy's `default` effect applies. Either way you get a `Decision`, never a
silent pass.

## Components

### Doctrine (`sentinel_policy/doctrine.py`)
Seven `Rule` dataclasses (`S1`..`S7`), exported as the immutable tuple
`DOCTRINE` and looked up by id via `rule("S3")`. The doctrine is the published
"why": every policy rule names the principle it enforces, so any decision is
traceable to a stated principle rather than a vibe. A module-level assertion
fails fast if the doctrine is ever edited into fewer/more than seven unique
rules.

### Conditions (`sentinel_policy/conditions.py`)
A small, safe matcher. A rule's `match` is a mapping of **dotted field path** →
**expected**, where expected is a scalar (equality, or glob if it contains
wildcards) or an operator object. The operator set covers equality/sets (`eq`,
`ne`, `in`, `nin`, `contains`, `subset`, `superset`), text (`glob`, `regex`,
`startswith`, `endswith`), numbers (`gt`, `ge`, `lt`, `le`, `between`),
presence/size (`exists`, `len_eq`, `len_gt`, `len_lt`), network (`cidr`), time
(`time_window`, wrapping past midnight), and logical composition (`all_`,
`any_`, `not_`). All entries in a match must hold (logical AND). Every operator
is **total** — a malformed value fails closed, never raises — and there is no
expression language and no `eval`, so policies stay data you can review, diff,
and sign without executing anything.

### Policy engine (`sentinel_policy/policy.py`)
- **`Effect`** — `allow` / `deny` / `require_approval`.
- **`Decision`** — frozen result: `effect`, `rule`, `doctrine`, `reason`,
  `obligations`, plus the `allowed` property (only an explicit `allow` is
  truthy) and `as_dict()`.
- **`Policy`** — holds the sorted rules and default; `evaluate(directive)`
  returns a `Decision`; `explain(directive)` returns a full `Trace` (every rule
  considered, which matched, which decided) for dry-run/simulation;
  `doctrine_coverage()` reports enforced vs uncovered principles; `validate()`
  reports problems (duplicate ids, unknown doctrine references, unknown/badly
  shaped operators, tier-less approvals, uncompilable regex); `to_dict()`
  round-trips the canonical form.
- **`as_gate_evaluator(defer_on_default=...)`** — returns a `Callable` for
  composition. With `defer_on_default=True` it returns `None` when only the
  default applied, letting a host gate decide — so you can stack an org doctrine
  above a team policy (see demo 4).
- **`load_policy(path)`** — read a JSON policy from disk.

### Additive modules (all pure, dependency-free)
- **`diffing.py`** — `diff_policies(old, new)` → a `PolicyDiff` of added /
  removed / changed rules keyed by id, with a `loosens_control` flag (a
  deny→allow, a dropped gate, or a relaxed default) that a release gate acts on.
- **`audit.py`** — `AuditLog` appends each decision as one JSON object per line
  (append-only); `replay()` / `replay_file()` fold a log back into a
  `ReplaySummary` (counts by effect/doctrine/actor, denials, approvals held,
  unlabeled-record warnings). Serves Immutable Record (S4) + Provable Refusal (S7).
- **`report.py`** — `build_report(policy)` folds lint + doctrine coverage +
  effect mix + operators used + dead-rule detection into one `Report` a CI job
  can assert on.
- **`ratelimit.py`** — a sliding-window `RateLimiter` over a pluggable
  `CounterStore` (in-memory by default), deterministic under an injected clock;
  `key_from_directive` renders a scope key from a directive template.
- **`serialization.py`** — `to_yaml` / `from_yaml` (stdlib fallback, PyYAML if
  present) and `to_rego` (a readable OPA-Rego-subset export, doctrine cited).

### CLI (`sentinel_policy/cli.py`)
`sentinel doctrine` prints the seven rules; `lint` validates a file; `eval`
evaluates a directive (exit 0 if allowed, 2 otherwise); `explain` prints the full
reasoning trace; `coverage` and `report` audit the policy itself; `diff`
compares two versions; `replay` aggregates a decision log; `export` emits YAML /
Rego / JSON; and `ci` is a build gate (validity + coverage floor + dead rules +
loosening-vs-baseline, exit 1 on failure).

## Composability

```mermaid
flowchart TB
    teamdir[Directive] --> team[Team policy<br/>as_gate_evaluator defer=True]
    team -- decided --> out[Decision]
    team -- None / default --> org[Org doctrine<br/>Policy.evaluate]
    org --> out
```

Because a policy compiles to a pure evaluator, layering is just function
composition: doctrine → org → team, no framework required. The same `Decision`
shape (`.allowed`, `.rule`, `.reason`, `.as_dict()`) drops straight into
[`agentledger`](https://github.com/cognis-digital/agentledger)'s `PolicyGate`
hook — sentinel-policy decides, agentledger signs and records.

## Why these choices

- **Policy as data, not code.** Reviewable, diffable, signable; no `eval`, no
  arbitrary execution at enforcement time.
- **Decision-only, dependency-free.** The engine never performs the action and
  never reaches the network — it only renders a verdict, so it drops into any
  host without pulling in a stack.
- **Every verdict cites a published rule.** Provable Refusal (S7) is structural:
  even the default branch returns a named `Decision`. Silence is never an
  outcome.

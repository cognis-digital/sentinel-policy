"""sentinel-policy command line.

    sentinel doctrine                     # print the seven SENTINEL rules
    sentinel lint POLICY.json             # validate a policy file
    sentinel eval POLICY.json --action deploy --param env=prod [--actor alice]
    sentinel explain POLICY.json --action deploy --param env=prod   # full trace
    sentinel coverage POLICY.json [--json]        # which doctrine rules it enforces
    sentinel report POLICY.json [--json]          # lint + coverage + shape
    sentinel diff OLD.json NEW.json [--json]      # what changed between two policies
    sentinel replay LOG.jsonl [--json]            # aggregate a decision log
    sentinel export POLICY.json --format yaml|rego|json
    sentinel ci POLICY.json [--min-coverage N] [--baseline OLD.json] [--fail-on-loosen]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .audit import replay_file
from .diffing import diff_policies
from .doctrine import DOCTRINE
from .policy import load_policy
from .report import build_report
from .serialization import to_rego, to_yaml


def _load_or_exit(path: str):
    try:
        return load_policy(path)
    except FileNotFoundError as exc:
        raise SystemExit(f"error: {exc}")
    except ValueError as exc:  # PolicyError subclasses ValueError
        raise SystemExit(f"error: {exc}")


def _parse_params(pairs):
    """Turn ["env=prod", "irreversible=true", "n=3"] into a typed dict."""
    out = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"bad --param {pair!r}; expected key=value")
        k, v = pair.split("=", 1)
        if v.lower() in ("true", "false"):
            out[k] = v.lower() == "true"
        else:
            try:
                out[k] = int(v)
            except ValueError:
                try:
                    out[k] = float(v)
                except ValueError:
                    out[k] = v
    return out


def _directive(args) -> dict:
    return {"actor": args.actor, "action": args.action,
            "params": _parse_params(args.param)}


def cmd_doctrine(_args) -> int:
    for r in DOCTRINE:
        print(f"{r.id}  {r.name}")
        print(f"    {r.statement}")
        print(f"    why: {r.rationale}\n")
    return 0


def cmd_lint(args) -> int:
    policy = _load_or_exit(args.policy)
    problems = policy.validate()
    if problems:
        print(f"INVALID: {args.policy}")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: {args.policy} ({len(policy.rules)} rules, default={policy.default.value})")
    return 0


def cmd_eval(args) -> int:
    policy = _load_or_exit(args.policy)
    directive = _directive(args)
    decision = policy.evaluate(directive)
    print(json.dumps({"directive": directive, "decision": decision.as_dict()}, indent=2))
    return 0 if decision.allowed else 2


def cmd_explain(args) -> int:
    policy = _load_or_exit(args.policy)
    trace = policy.explain(_directive(args))
    if args.json:
        print(json.dumps(trace.as_dict(), indent=2))
    else:
        print(trace.render())
    return 0 if trace.decision.allowed else 2


def cmd_coverage(args) -> int:
    policy = _load_or_exit(args.policy)
    cov = policy.doctrine_coverage()
    if args.json:
        print(json.dumps(cov, indent=2))
        return 0
    print(f"Doctrine coverage for {args.policy}:")
    for rid, doc in cov["by_rule"].items():
        print(f"  {rid:<28} -> {doc or '(uncited)'}")
    print(f"\n  covered  : {', '.join(cov['covered']) or '(none)'}")
    print(f"  uncovered: {', '.join(cov['uncovered']) or '(none)'}")
    print(f"  {len(cov['covered'])}/{len(cov['covered']) + len(cov['uncovered'])} "
          f"SENTINEL principles enforced")
    return 0


def cmd_report(args) -> int:
    policy = _load_or_exit(args.policy)
    rep = build_report(policy)
    if args.json:
        print(json.dumps(rep.as_dict(), indent=2))
    else:
        print(rep.render())
    return 0 if rep.valid else 1


def cmd_diff(args) -> int:
    old = _load_or_exit(args.old)
    new = _load_or_exit(args.new)
    d = diff_policies(old, new)
    if args.json:
        print(json.dumps(d.as_dict(), indent=2))
    else:
        print(f"diff {args.old} -> {args.new}:")
        print(d.render())
    return 0


def cmd_replay(args) -> int:
    try:
        summary = replay_file(args.log)
    except FileNotFoundError as exc:
        raise SystemExit(f"error: {exc}")
    if args.json:
        print(json.dumps(summary.as_dict(), indent=2))
    else:
        print(f"replay of {args.log}:")
        print(summary.render())
    return 0


def cmd_export(args) -> int:
    policy = _load_or_exit(args.policy)
    if args.format == "yaml":
        print(to_yaml(policy))
    elif args.format == "rego":
        print(to_rego(policy))
    else:  # json
        print(json.dumps(policy.to_dict(), indent=2))
    return 0


def cmd_ci(args) -> int:
    """A CI gate: fail the build on an invalid policy, insufficient doctrine
    coverage, dead rules, or (with a baseline) a change that loosens control."""
    policy = _load_or_exit(args.policy)
    rep = build_report(policy)
    ok = True
    print(f"sentinel ci: {args.policy}")
    if not rep.valid:
        ok = False
        print("  FAIL: policy is invalid")
        for p in rep.problems:
            print(f"    - {p}")
    else:
        print("  OK  : policy is well-formed")

    if rep.dead_rules:
        ok = False
        print(f"  FAIL: unreachable rules: {', '.join(rep.dead_rules)}")

    if args.min_coverage is not None:
        if rep.coverage_pct + 1e-9 < args.min_coverage:
            ok = False
            print(f"  FAIL: doctrine coverage {rep.coverage_pct:.0f}% "
                  f"< required {args.min_coverage:.0f}%")
        else:
            print(f"  OK  : doctrine coverage {rep.coverage_pct:.0f}% "
                  f">= {args.min_coverage:.0f}%")

    if args.baseline:
        base = _load_or_exit(args.baseline)
        d = diff_policies(base, policy)
        if d.loosens_control and args.fail_on_loosen:
            ok = False
            print("  FAIL: change loosens control vs baseline:")
            print("    " + d.render().replace("\n", "\n    "))
        elif d.loosens_control:
            print("  WARN: change loosens control vs baseline (not failing)")
        else:
            print("  OK  : change does not loosen control vs baseline")

    print("  =>", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sentinel-policy {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctrine", help="print the SENTINEL doctrine").set_defaults(func=cmd_doctrine)

    pl = sub.add_parser("lint", help="validate a policy file")
    pl.add_argument("policy")
    pl.set_defaults(func=cmd_lint)

    def _add_directive(sp):
        sp.add_argument("policy")
        sp.add_argument("--action", required=True)
        sp.add_argument("--actor", default="unknown")
        sp.add_argument("--param", action="append", help="key=value (repeatable)")

    pe = sub.add_parser("eval", help="evaluate a directive against a policy")
    _add_directive(pe)
    pe.set_defaults(func=cmd_eval)

    px = sub.add_parser("explain", help="evaluate and print the full reasoning trace")
    _add_directive(px)
    px.add_argument("--json", action="store_true", help="emit JSON")
    px.set_defaults(func=cmd_explain)

    pc = sub.add_parser("coverage", help="report doctrine coverage of a policy")
    pc.add_argument("policy")
    pc.add_argument("--json", action="store_true", help="emit JSON")
    pc.set_defaults(func=cmd_coverage)

    pr = sub.add_parser("report", help="lint + coverage + shape report")
    pr.add_argument("policy")
    pr.add_argument("--json", action="store_true", help="emit JSON")
    pr.set_defaults(func=cmd_report)

    pd = sub.add_parser("diff", help="structured diff between two policy files")
    pd.add_argument("old")
    pd.add_argument("new")
    pd.add_argument("--json", action="store_true", help="emit JSON")
    pd.set_defaults(func=cmd_diff)

    prp = sub.add_parser("replay", help="aggregate a JSONL decision log")
    prp.add_argument("log")
    prp.add_argument("--json", action="store_true", help="emit JSON")
    prp.set_defaults(func=cmd_replay)

    pex = sub.add_parser("export", help="export a policy to yaml / rego / json")
    pex.add_argument("policy")
    pex.add_argument("--format", choices=["yaml", "rego", "json"], default="yaml")
    pex.set_defaults(func=cmd_export)

    pci = sub.add_parser("ci", help="CI gate: validity, coverage, dead rules, loosening")
    pci.add_argument("policy")
    pci.add_argument("--min-coverage", type=float, default=None,
                     help="fail if doctrine coverage %% is below this")
    pci.add_argument("--baseline", help="compare against this policy; report loosening")
    pci.add_argument("--fail-on-loosen", action="store_true",
                     help="fail the gate if the change loosens control vs baseline")
    pci.set_defaults(func=cmd_ci)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

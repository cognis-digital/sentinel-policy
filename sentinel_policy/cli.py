"""sentinel-policy command line.

    sentinel doctrine                     # print the seven SENTINEL rules
    sentinel lint POLICY.json             # validate a policy file
    sentinel eval POLICY.json --action deploy --param env=prod [--actor alice]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .doctrine import DOCTRINE
from .policy import load_policy


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


def cmd_doctrine(_args) -> int:
    for r in DOCTRINE:
        print(f"{r.id}  {r.name}")
        print(f"    {r.statement}")
        print(f"    why: {r.rationale}\n")
    return 0


def cmd_lint(args) -> int:
    policy = load_policy(args.policy)
    problems = policy.validate()
    if problems:
        print(f"INVALID: {args.policy}")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: {args.policy} ({len(policy.rules)} rules, default={policy.default.value})")
    return 0


def cmd_eval(args) -> int:
    policy = load_policy(args.policy)
    directive = {
        "actor": args.actor,
        "action": args.action,
        "params": _parse_params(args.param),
    }
    decision = policy.evaluate(directive)
    print(json.dumps({"directive": directive, "decision": decision.as_dict()}, indent=2))
    return 0 if decision.allowed else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sentinel-policy {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctrine", help="print the SENTINEL doctrine").set_defaults(func=cmd_doctrine)

    pl = sub.add_parser("lint", help="validate a policy file")
    pl.add_argument("policy")
    pl.set_defaults(func=cmd_lint)

    pe = sub.add_parser("eval", help="evaluate a directive against a policy")
    pe.add_argument("policy")
    pe.add_argument("--action", required=True)
    pe.add_argument("--actor", default="unknown")
    pe.add_argument("--param", action="append", help="key=value (repeatable)")
    pe.set_defaults(func=cmd_eval)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Scenario 20 - the CLI, driven in-process.

Everything the `sentinel` command does is also callable as a function, so this
demo drives the real CLI entrypoint (`sentinel_policy.cli.main`) for each
subcommand - doctrine, lint, coverage, eval - and reports the exit code each
returned. This is the same path `sentinel ...` takes from a shell, minus the
shell, so it runs anywhere and exits 0.
"""
import os

from _common import banner
from sentinel_policy.cli import main as cli

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(REPO_ROOT, "policies", "example.json")


def run(label, argv, expected_codes):
    print(f"\n$ sentinel {' '.join(argv)}    # {label}")
    print("  " + "-" * 68)
    rc = cli(argv)
    print(f"  -> exit {rc}")
    assert rc in expected_codes, f"{label}: got exit {rc}, want {expected_codes}"
    return rc


def main() -> None:
    banner("CLI WALKTHROUGH  -  every subcommand, real exit codes")

    run("print the seven rules", ["doctrine"], {0})
    run("validate the shipped policy", ["lint", EXAMPLE], {0})
    run("report doctrine coverage", ["coverage", EXAMPLE], {0})
    run("evaluate an allowed action", ["eval", EXAMPLE, "--action", "read.logs"], {0})
    run("evaluate a gated action (exit 2)",
        ["eval", EXAMPLE, "--action", "deploy", "--param", "env=prod"], {2})
    run("evaluate a denied action (exit 2)",
        ["eval", EXAMPLE, "--action", "data.export"], {2})

    print("\nAll subcommands ran through the real entrypoint. `eval` returns 0")
    print("for allow and 2 for deny/require-approval, so it scripts in a pipeline.")


if __name__ == "__main__":
    main()

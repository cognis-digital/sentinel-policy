"""Smoke-test the demo scenarios: each must import and run main() without error.

The demos use only the real public API, so running them here guarantees the
README's "## Demos" claims stay true and the examples never drift from the code.
"""
import importlib
import os
import sys

import pytest

DEMOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")
sys.path.insert(0, DEMOS_DIR)

SCENARIOS = [
    "01_agent_builder_gate",
    "02_security_least_authority",
    "03_compliance_doctrine_coverage",
    "04_platform_layered_policies",
    "05_provable_refusal_log",
    "21_new_condition_operators",
    "22_explain_trace",
    "23_policy_diff",
    "24_audit_replay",
    "25_rate_limit",
    "26_ci_gate_and_export",
]


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs(name, capsys):
    mod = importlib.import_module(name)
    mod.main()                     # asserts inside the demo guard correctness
    out = capsys.readouterr().out
    assert out.strip(), f"{name} produced no output"


def test_run_all_lists_every_scenario():
    run_all = importlib.import_module("run_all")
    assert run_all.SCENARIOS == SCENARIOS

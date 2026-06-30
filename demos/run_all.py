"""Run every demo scenario end to end.

    python demos/run_all.py

Each scenario is independent, uses only the real sentinel-policy API, needs no
network, and exits 0 - so they double as smoke tests.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_agent_builder_gate",
    "02_security_least_authority",
    "03_compliance_doctrine_coverage",
    "04_platform_layered_policies",
    "05_provable_refusal_log",
    "06_doctrine_coverage_report",
    "07_lint_catches_mistakes",
    "08_malformed_policy_errors",
    "09_priority_conflict_resolution",
    "10_reversibility_gate",
    "11_numeric_thresholds",
    "12_attributed_intent",
    "13_boundary_integrity",
    "14_gate_evaluator_integration",
    "15_three_tier_stack",
    "16_load_lint_from_disk",
    "17_default_policy_modes",
    "18_audit_log_jsonl",
    "19_doctrine_walkthrough",
    "20_cli_walkthrough",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 72)
    print("  All demo scenarios completed.")
    print("=" * 72)


if __name__ == "__main__":
    main()

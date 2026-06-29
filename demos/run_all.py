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

"""Scenario 18 - audit: emit a JSONL decision log and replay/aggregate it.

Provable Refusal (S7) means every decision is a record. This demo evaluates a
batch of directives, serializes each into a JSONL line (one object per line -
the format log pipelines ingest), then reads the log back and produces an audit
summary: counts by effect and the doctrine rules invoked. The log is the
evidence; the summary is what you hand the auditor.
"""
import json
from collections import Counter

from _common import banner, example_policy


def main() -> None:
    policy = example_policy()
    banner("AUDIT LOG (JSONL)  -  every decision is a replayable record")

    directives = [
        {"actor": "alice", "action": "read.logs", "params": {}},
        {"actor": "bob", "action": "deploy", "params": {"env": "prod"}},
        {"actor": "carol", "action": "db.drop", "params": {"irreversible": True}},
        {"actor": "etl", "action": "pii.export", "params": {}},
        {"actor": "dave", "action": "deploy", "params": {"env": "staging"}},
        {"actor": "eve", "action": "unknown.op", "params": {}},
    ]

    # 1) produce the log (one JSON object per line)
    lines = []
    for req in directives:
        decision = policy.evaluate(req)
        lines.append(json.dumps({"actor": req["actor"], "action": req["action"],
                                 **decision.as_dict()}, separators=(",", ":")))
    log = "\n".join(lines)
    print(f"\nDecision log ({len(lines)} JSONL records):\n")
    for ln in lines:
        print("  " + ln)

    # 2) replay it - exactly what a downstream auditor would do
    by_effect = Counter()
    by_doctrine = Counter()
    for ln in log.splitlines():
        rec = json.loads(ln)
        by_effect[rec["effect"]] += 1
        if rec["doctrine"]:
            by_doctrine[rec["doctrine"]] += 1

    print("\nReplayed summary:")
    for effect, n in sorted(by_effect.items()):
        print(f"  {effect:<18}: {n}")
    print("  doctrine rules invoked:",
          ", ".join(f"{k}x{v}" for k, v in sorted(by_doctrine.items())))

    assert sum(by_effect.values()) == len(directives)
    # not one directive produced an unlabeled outcome
    assert all(json.loads(ln)["rule"] for ln in log.splitlines())

    print("\nEvery directive - allowed or refused - is a structured line you can")
    print("grep, replay, and aggregate. That is a refusal you can prove.")


if __name__ == "__main__":
    main()

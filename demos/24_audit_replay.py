"""Scenario 24 - AuditLog + replay: every decision is a durable record.

Immutable Record (S4) + Provable Refusal (S7): decisions are appended to a JSONL
log (one object per line, the shape log pipelines ingest), then replayed into an
audit summary. The log is the evidence; the summary is what you hand the auditor.
"""
import io

from _common import banner, example_policy
from sentinel_policy import AuditLog, replay


def main() -> None:
    policy = example_policy()
    banner("AUDIT LOG + REPLAY  -  append-only JSONL, then aggregate")

    directives = [
        {"actor": "alice", "action": "read.logs", "params": {}},
        {"actor": "bob", "action": "deploy", "params": {"env": "prod"}},
        {"actor": "carol", "action": "db.drop", "params": {"irreversible": True}},
        {"actor": "etl", "action": "pii.export", "params": {}},
        {"actor": "dave", "action": "deploy", "params": {"env": "staging"}},
        {"actor": "eve", "action": "unknown.op", "params": {}},
    ]

    # write the log to an in-memory stream (a file works identically)
    buf = io.StringIO()
    with AuditLog(buf, clock=lambda: "2026-01-01T00:00:00Z") as log:
        log.write_many(policy, directives)
        assert log.count == len(directives)

    print(f"\nDecision log ({log.count} JSONL records):\n")
    for line in buf.getvalue().splitlines():
        print("  " + line)

    # replay - exactly what a downstream auditor would do
    summary = replay(buf.getvalue().splitlines())
    print("\nReplayed summary:")
    print("  " + summary.render().replace("\n", "\n  "))

    assert summary.total == len(directives)
    assert not summary.unlabeled, "no directive produced a silent outcome"
    assert summary.refusals >= 1

    print("\nEvery directive - allowed or refused - is a structured line you can")
    print("grep, replay, and aggregate. That is a refusal you can prove.")


if __name__ == "__main__":
    main()

"""Tests for the JSONL audit log + replay."""
import io
import json

import pytest

from sentinel_policy import AuditLog, Policy, record, replay, replay_file, to_jsonl


def _policy():
    return Policy.from_dict({
        "name": "t", "default": "deny",
        "rules": [
            {"id": "reads", "effect": "allow", "doctrine": "S2",
             "match": {"action": "read.*"}},
            {"id": "gate", "effect": "require_approval", "tier": "high",
             "doctrine": "S3", "match": {"params.env": {"eq": "prod"}}},
        ],
    })


def test_record_shape():
    p = _policy()
    d = {"actor": "alice", "action": "read.logs", "params": {}}
    rec = record(d, p.evaluate(d), at="2026-01-01T00:00:00Z")
    assert rec["actor"] == "alice"
    assert rec["effect"] == "allow"
    assert rec["rule"] == "reads"
    assert rec["ts"] == "2026-01-01T00:00:00Z"


def test_write_to_stream_and_replay():
    p = _policy()
    buf = io.StringIO()
    directives = [
        {"actor": "a", "action": "read.x", "params": {}},
        {"actor": "b", "action": "deploy", "params": {"env": "prod"}},
        {"actor": "c", "action": "unknown", "params": {}},
    ]
    with AuditLog(buf, clock=lambda: "T") as log:
        log.write_many(p, directives)
        assert log.count == 3
    lines = buf.getvalue().splitlines()
    assert len(lines) == 3
    s = replay(lines)
    assert s.total == 3
    assert s.by_effect["allow"] == 1
    assert s.by_effect["require_approval"] == 1
    assert s.by_effect["deny"] == 1
    assert s.by_doctrine["S2"] == 1
    assert s.approvals and s.denied
    assert s.refusals == 1


def test_write_requires_context_manager():
    log = AuditLog(io.StringIO())
    with pytest.raises(RuntimeError):
        log.write({"action": "x"}, _policy().evaluate({"action": "x"}))


def test_replay_ignores_blank_lines():
    p = _policy()
    line = to_jsonl([record({"actor": "a", "action": "read.x"},
                            p.evaluate({"action": "read.x"}), at="T")])
    s = replay([line, "", "   "])
    assert s.total == 1


def test_replay_flags_unlabeled_record():
    s = replay([json.dumps({"effect": "allow", "rule": None})])
    assert s.unlabeled
    assert "WARNING" in s.render()


def test_write_to_file_and_replay_file(tmp_path):
    p = _policy()
    path = tmp_path / "log.jsonl"
    with AuditLog(str(path), clock=lambda: "T") as log:
        log.write_many(p, [{"actor": "a", "action": "read.x", "params": {}}])
    # append again: log is append-only
    with AuditLog(str(path), clock=lambda: "T") as log:
        log.write_many(p, [{"actor": "b", "action": "deploy", "params": {"env": "prod"}}])
    s = replay_file(str(path))
    assert s.total == 2
    assert s.by_actor["a"] == 1 and s.by_actor["b"] == 1


def test_replay_missing_file():
    with pytest.raises(FileNotFoundError):
        replay_file("does-not-exist.jsonl")

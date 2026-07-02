"""Tests for the new CLI subcommands."""
import json

import pytest

from sentinel_policy.cli import main

EXAMPLE = "policies/example.json"


def run(argv):
    return main(argv)


def test_explain_text(capsys):
    rc = run(["explain", EXAMPLE, "--action", "deploy", "--param", "env=prod"])
    out = capsys.readouterr().out
    assert "verdict:" in out
    assert "gate-prod-deploy" in out
    assert rc == 2  # require_approval is not "allowed"


def test_explain_json(capsys):
    rc = run(["explain", EXAMPLE, "--action", "read.logs", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["decided_by"] == "reads-are-fine"
    assert data["decision"]["allowed"] is True
    assert rc == 0


def test_report_text_and_json(capsys):
    assert run(["report", EXAMPLE]) == 0
    assert "coverage" in capsys.readouterr().out
    assert run(["report", EXAMPLE, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is True


def test_coverage_command(capsys):
    assert run(["coverage", EXAMPLE, "--json"]) == 0
    cov = json.loads(capsys.readouterr().out)
    assert "S2" in cov["covered"]


def test_export_formats(capsys):
    assert run(["export", EXAMPLE, "--format", "rego"]) == 0
    assert "package sentinel" in capsys.readouterr().out
    assert run(["export", EXAMPLE, "--format", "yaml"]) == 0
    assert "rules" in capsys.readouterr().out
    assert run(["export", EXAMPLE, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "prod-controls"


def test_diff_command(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"name": "t", "default": "deny",
                               "rules": [{"id": "a", "effect": "deny",
                                          "match": {"action": "x"}}]}))
    new.write_text(json.dumps({"name": "t", "default": "deny",
                               "rules": [{"id": "a", "effect": "allow",
                                          "match": {"action": "x"}}]}))
    rc = run(["diff", str(old), str(new), "--json"])
    assert rc == 0
    d = json.loads(capsys.readouterr().out)
    assert d["loosens_control"] is True


def test_replay_command(tmp_path, capsys):
    log = tmp_path / "log.jsonl"
    log.write_text(
        json.dumps({"effect": "allow", "rule": "r", "doctrine": "S2", "actor": "a"}) + "\n" +
        json.dumps({"effect": "deny", "rule": "d", "doctrine": "S6", "actor": "b"}) + "\n"
    )
    rc = run(["replay", str(log), "--json"])
    assert rc == 0
    s = json.loads(capsys.readouterr().out)
    assert s["total"] == 2
    assert s["refusals"] == 1


def test_ci_passes_on_good_policy(capsys):
    rc = run(["ci", EXAMPLE, "--min-coverage", "30"])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_ci_fails_on_coverage_shortfall(capsys):
    rc = run(["ci", EXAMPLE, "--min-coverage", "100"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_ci_fails_on_loosening_baseline(tmp_path, capsys):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"name": "t", "default": "deny",
                                "rules": [{"id": "a", "effect": "deny",
                                           "doctrine": "S6", "match": {"action": "x"}}]}))
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps({"name": "t", "default": "deny",
                               "rules": [{"id": "a", "effect": "allow",
                                          "doctrine": "S6", "match": {"action": "x"}}]}))
    rc = run(["ci", str(cur), "--baseline", str(base), "--fail-on-loosen"])
    assert rc == 1
    assert "loosens control" in capsys.readouterr().out


def test_ci_fails_on_dead_rule(tmp_path, capsys):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"name": "t", "default": "deny", "rules": [
        {"id": "catch", "effect": "allow", "match": {}},
        {"id": "dead", "effect": "deny", "match": {"action": "x"}},
    ]}))
    rc = run(["ci", str(pol)])
    assert rc == 1
    assert "unreachable" in capsys.readouterr().out


def test_missing_file_clean_error():
    with pytest.raises(SystemExit):
        run(["report", "no-such-file.json"])

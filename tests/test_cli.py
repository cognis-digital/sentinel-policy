"""CLI tests: drive ``sentinel_policy.cli.main`` in-process and assert exit
codes, output, and that bad input produces a clean message (not a traceback).
"""
import json
from pathlib import Path

import pytest

from sentinel_policy.cli import main

EXAMPLE = str(Path(__file__).resolve().parent.parent / "policies" / "example.json")


def test_doctrine_prints_all_seven(capsys):
    assert main(["doctrine"]) == 0
    out = capsys.readouterr().out
    for sid in ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]:
        assert sid in out


def test_lint_ok_returns_zero(capsys):
    assert main(["lint", EXAMPLE]) == 0
    assert "OK" in capsys.readouterr().out


def test_lint_invalid_returns_one(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "name": "p", "default": "deny",
        "rules": [{"id": "r", "doctrine": "S99", "effect": "deny",
                   "match": {"a": {"nope": 1}}}],
    }), encoding="utf-8")
    assert main(["lint", str(bad)]) == 1
    out = capsys.readouterr().out
    assert "INVALID" in out and "S99" in out


def test_lint_missing_file_clean_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as ei:
        main(["lint", str(tmp_path / "nope.json")])
    # SystemExit carries a clean message string, not a traceback
    assert "not found" in str(ei.value)


def test_lint_bad_json_clean_error(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit) as ei:
        main(["lint", str(bad)])
    assert "invalid JSON" in str(ei.value)


def test_eval_allowed_exit_zero(capsys):
    rc = main(["eval", EXAMPLE, "--action", "read.logs"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"]["allowed"] is True


def test_eval_denied_exit_two(capsys):
    rc = main(["eval", EXAMPLE, "--action", "data.export"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"]["effect"] == "deny"


def test_eval_require_approval_exit_two(capsys):
    rc = main(["eval", EXAMPLE, "--action", "deploy", "--param", "env=prod"])
    assert rc == 2
    dec = json.loads(capsys.readouterr().out)["decision"]
    assert dec["effect"] == "require_approval"
    assert dec["obligations"]["tier"] == "high"


def test_eval_param_typing(capsys):
    # bool / int / float / str coercion in --param
    main(["eval", EXAMPLE, "--action", "x",
          "--param", "b=true", "--param", "n=3",
          "--param", "f=1.5", "--param", "s=hello"])
    params = json.loads(capsys.readouterr().out)["directive"]["params"]
    assert params == {"b": True, "n": 3, "f": 1.5, "s": "hello"}


def test_eval_bad_param_format_exits():
    with pytest.raises(SystemExit) as ei:
        main(["eval", EXAMPLE, "--action", "x", "--param", "noequalssign"])
    assert "bad --param" in str(ei.value)


def test_eval_actor_defaults_to_unknown(capsys):
    main(["eval", EXAMPLE, "--action", "read.logs"])
    assert json.loads(capsys.readouterr().out)["directive"]["actor"] == "unknown"


def test_coverage_text(capsys):
    assert main(["coverage", EXAMPLE]) == 0
    out = capsys.readouterr().out
    assert "covered" in out and "S2" in out


def test_coverage_json(capsys):
    assert main(["coverage", EXAMPLE, "--json"]) == 0
    cov = json.loads(capsys.readouterr().out)
    assert set(cov) == {"covered", "uncovered", "by_rule", "uncited_rules"}
    assert "S2" in cov["covered"]


def test_no_subcommand_errors():
    # subparsers are required -> argparse exits non-zero
    with pytest.raises(SystemExit):
        main([])


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert "sentinel-policy" in capsys.readouterr().out

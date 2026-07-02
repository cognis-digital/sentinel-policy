"""Tests for Policy.explain / simulate (dry-run + reasoning trace)."""
from sentinel_policy import Effect, Policy


def _policy():
    return Policy.from_dict({
        "name": "t", "default": "deny",
        "rules": [
            {"id": "reads", "effect": "allow", "doctrine": "S2",
             "match": {"action": "read.*"}},
            {"id": "gate-prod", "effect": "require_approval", "tier": "high",
             "doctrine": "S3", "match": {"params.env": {"eq": "prod"}}},
            {"id": "deny-export", "effect": "deny", "doctrine": "S6",
             "match": {"action": "*export*"}},
        ],
    })


def test_explain_records_every_step_until_match():
    t = _policy().explain({"action": "read.logs"})
    assert t.decided_by == "reads"
    assert t.matched_by_rule is True
    assert t.decision.effect is Effect.ALLOW
    assert [s.rule for s in t.steps] == ["reads", "gate-prod", "deny-export"]
    assert t.steps[0].matched and t.steps[0].reached
    # rules after the match are recorded as not reached
    assert all(not s.reached for s in t.steps[1:])


def test_explain_skips_non_matching_then_matches():
    t = _policy().explain({"action": "deploy", "params": {"env": "prod"}})
    assert t.decided_by == "gate-prod"
    assert t.steps[0].reached and not t.steps[0].matched  # reads considered, skipped
    assert t.steps[1].matched


def test_explain_falls_through_to_default():
    t = _policy().explain({"action": "whatever"})
    assert t.decided_by == "default"
    assert t.matched_by_rule is False
    assert t.decision.effect is Effect.DENY
    assert all(s.reached and not s.matched for s in t.steps)


def test_trace_as_dict_and_render():
    t = _policy().explain({"action": "read.logs"})
    d = t.as_dict()
    assert d["decided_by"] == "reads"
    assert d["decision"]["effect"] == "allow"
    assert len(d["steps"]) == 3
    text = t.render()
    assert "verdict:" in text
    assert "reads" in text


def test_simulate_batch():
    p = _policy()
    traces = p.simulate([{"action": "read.x"}, {"action": "data.export"}])
    assert traces[0].decision.effect is Effect.ALLOW
    assert traces[1].decision.effect is Effect.DENY


def test_explain_matches_evaluate():
    p = _policy()
    for directive in ({"action": "read.x"},
                      {"action": "deploy", "params": {"env": "prod"}},
                      {"action": "nope"}):
        assert p.explain(directive).decision.effect is p.evaluate(directive).effect

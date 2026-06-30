"""Evaluation-semantics tests: rule conflicts, priority, ties, the default
branch, REQUIRE_APPROVAL obligations, and the gate-evaluator composition hook.

These pin the *order of decision* — the part most likely to become a policy
bypass if it silently changes.
"""
from sentinel_policy import Decision, Effect, Policy

from sentinel_policy.policy import PolicyRule


def _p(rules, default="deny"):
    return Policy.from_dict({"name": "t", "default": default, "rules": rules})


# ---- first-match & priority --------------------------------------------

def test_first_matching_rule_wins_at_equal_priority():
    # equal priority -> declaration order decides (stable sort)
    p = _p([
        {"id": "first", "effect": "allow", "match": {"action": "x"}},
        {"id": "second", "effect": "deny", "match": {"action": "x"}},
    ])
    assert p.evaluate({"action": "x"}).rule == "first"


def test_higher_priority_overrides_declaration_order():
    p = _p([
        {"id": "low", "effect": "allow", "match": {"action": "x"}, "priority": 1},
        {"id": "high", "effect": "deny", "match": {"action": "x"}, "priority": 9},
    ])
    d = p.evaluate({"action": "x"})
    assert d.rule == "high" and d.effect is Effect.DENY


def test_conflict_deny_beats_allow_by_priority():
    # a security-shaped conflict: a broad allow and a targeted deny on the same
    # directive; the targeted deny is given higher priority and must win
    p = _p([
        {"id": "allow-all-reads", "effect": "allow",
         "match": {"action": "read.*"}, "priority": 1},
        {"id": "deny-read-secrets", "effect": "deny",
         "match": {"action": "read.secrets"}, "priority": 100},
    ])
    assert p.evaluate({"action": "read.secrets"}).rule == "deny-read-secrets"
    assert p.evaluate({"action": "read.logs"}).rule == "allow-all-reads"


def test_negative_priority_sorts_below_zero():
    p = _p([
        {"id": "zero", "effect": "deny", "match": {"action": "x"}, "priority": 0},
        {"id": "neg", "effect": "allow", "match": {"action": "x"}, "priority": -5},
    ])
    assert p.evaluate({"action": "x"}).rule == "zero"


# ---- default branch -----------------------------------------------------

def test_default_deny_when_no_rule_matches():
    p = _p([{"id": "r", "effect": "allow", "match": {"action": "x"}}])
    d = p.evaluate({"action": "y"})
    assert d.rule == "default" and d.effect is Effect.DENY
    assert not d.allowed
    assert d.reason == "default-deny"


def test_default_allow_policy():
    p = _p([{"id": "r", "effect": "deny", "match": {"action": "x"}}],
           default="allow")
    assert p.evaluate({"action": "anything-else"}).allowed
    assert not p.evaluate({"action": "x"}).allowed


def test_default_require_approval_policy():
    p = _p([], default="require_approval")
    d = p.evaluate({"action": "whatever"})
    assert d.effect is Effect.REQUIRE_APPROVAL and not d.allowed


def test_empty_policy_falls_to_default():
    p = _p([])
    assert p.evaluate({"action": "x"}).rule == "default"


# ---- obligations on REQUIRE_APPROVAL -----------------------------------

def test_require_approval_sets_obligations_and_tier():
    p = _p([{"id": "gate", "effect": "require_approval", "tier": "high",
             "match": {"action": "deploy"}}])
    d = p.evaluate({"action": "deploy"})
    assert d.obligations["approval_required"] is True
    assert d.obligations["tier"] == "high"


def test_require_approval_without_tier_still_flags_approval():
    rule = PolicyRule(id="g", effect=Effect.REQUIRE_APPROVAL,
                      match={"action": "deploy"})
    p = Policy("t", [rule])
    d = p.evaluate({"action": "deploy"})
    assert d.obligations.get("approval_required") is True
    assert "tier" not in d.obligations


def test_allow_and_deny_carry_no_obligations():
    p = _p([
        {"id": "a", "effect": "allow", "match": {"action": "r"}},
        {"id": "d", "effect": "deny", "match": {"action": "w"}},
    ])
    assert p.evaluate({"action": "r"}).obligations == {}
    assert p.evaluate({"action": "w"}).obligations == {}


# ---- Decision shape -----------------------------------------------------

def test_decision_allowed_only_for_allow():
    assert Decision(Effect.ALLOW, "r").allowed
    assert not Decision(Effect.DENY, "r").allowed
    assert not Decision(Effect.REQUIRE_APPROVAL, "r").allowed


def test_decision_is_frozen():
    import dataclasses
    d = Decision(Effect.ALLOW, "r")
    try:
        d.rule = "other"
        assert False, "Decision should be immutable"
    except dataclasses.FrozenInstanceError:
        pass


def test_decision_as_dict_keys():
    d = Decision(Effect.REQUIRE_APPROVAL, "r", doctrine="S3",
                 reason="why", obligations={"approval_required": True})
    out = d.as_dict()
    assert out == {
        "allowed": False, "effect": "require_approval", "rule": "r",
        "doctrine": "S3", "reason": "why",
        "obligations": {"approval_required": True},
    }


def test_two_rules_with_same_match_distinct_obligations():
    # distinct Decisions don't share the obligations dict (mutable-default trap)
    p = _p([
        {"id": "g1", "effect": "require_approval", "tier": "high",
         "match": {"action": "a"}},
        {"id": "g2", "effect": "require_approval", "tier": "low",
         "match": {"action": "b"}},
    ])
    d1 = p.evaluate({"action": "a"})
    d2 = p.evaluate({"action": "b"})
    assert d1.obligations is not d2.obligations
    assert d1.obligations["tier"] == "high"
    assert d2.obligations["tier"] == "low"


# ---- gate evaluator composition ----------------------------------------

def test_gate_evaluator_defer_returns_none_on_default():
    p = _p([{"id": "r", "effect": "allow", "match": {"action": "x"}}])
    ev = p.as_gate_evaluator(defer_on_default=True)
    assert ev({"action": "x"}) is not None
    assert ev({"action": "unmatched"}) is None


def test_gate_evaluator_no_defer_always_decides():
    p = _p([{"id": "r", "effect": "allow", "match": {"action": "x"}}])
    ev = p.as_gate_evaluator(defer_on_default=False)
    d = ev({"action": "unmatched"})
    assert d is not None and d.rule == "default"


def test_layered_org_above_team():
    # team is permissive on dev; org gates irreversible. Compose by deferral.
    team = _p([{"id": "team-dev", "effect": "allow",
                "match": {"params.env": {"in": ["dev"]}}}])
    org = _p([{"id": "org-irrev", "effect": "require_approval", "tier": "high",
               "match": {"params.irreversible": {"eq": True}}}])
    team_ev = team.as_gate_evaluator(defer_on_default=True)

    def layered(directive):
        d = team_ev(directive)
        return d if d is not None else org.evaluate(directive)

    # dev action the team owns -> allowed
    assert layered({"action": "x", "params": {"env": "dev"}}).allowed
    # something the team has no opinion on -> org default deny
    assert not layered({"action": "x", "params": {"env": "prod"}}).allowed
    # irreversible but in a namespace the team owns: team matched first (allows)
    # — demonstrates why org-as-hard-overlay (eval directly) is needed for S5
    org_overlay = org.evaluate({"action": "x",
                                "params": {"env": "dev", "irreversible": True}})
    assert org_overlay.effect is Effect.REQUIRE_APPROVAL

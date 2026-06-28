from pathlib import Path

from sentinel_policy import Effect, Policy, load_policy

EXAMPLE = Path(__file__).resolve().parent.parent / "policies" / "example.json"


def test_load_example_is_valid():
    policy = load_policy(str(EXAMPLE))
    assert policy.name == "prod-controls"
    assert policy.default is Effect.DENY
    assert policy.validate() == []


def test_allow_read():
    policy = load_policy(str(EXAMPLE))
    d = policy.evaluate({"action": "read.logs", "params": {}})
    assert d.allowed
    assert d.doctrine == "S2"


def test_require_approval_prod_deploy():
    policy = load_policy(str(EXAMPLE))
    d = policy.evaluate({"action": "deploy", "params": {"env": "prod"}})
    assert d.effect is Effect.REQUIRE_APPROVAL
    assert not d.allowed
    assert d.obligations.get("approval_required") is True
    assert d.obligations.get("tier") == "high"
    assert d.doctrine == "S3"


def test_deny_export_crosses_boundary():
    policy = load_policy(str(EXAMPLE))
    d = policy.evaluate({"action": "data.export", "params": {}})
    assert d.effect is Effect.DENY
    assert d.doctrine == "S6"


def test_default_deny_for_unmatched():
    policy = load_policy(str(EXAMPLE))
    d = policy.evaluate({"action": "mystery", "params": {}})
    assert d.rule == "default"
    assert not d.allowed


def test_priority_ordering():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [
            {"id": "low", "effect": "allow", "match": {"action": "x"}, "priority": 1},
            {"id": "high", "effect": "deny", "match": {"action": "x"}, "priority": 10},
        ],
    })
    d = policy.evaluate({"action": "x"})
    assert d.rule == "high"  # higher priority wins regardless of order


def test_validate_flags_bad_doctrine_and_op():
    policy = Policy.from_dict({
        "name": "p", "default": "deny",
        "rules": [
            {"id": "r1", "effect": "allow", "doctrine": "S42", "match": {"a": "b"}},
            {"id": "r2", "effect": "deny", "match": {"a": {"approx": 1}}},
            {"id": "r1", "effect": "deny", "match": {}},
        ],
    })
    problems = policy.validate()
    assert any("S42" in p for p in problems)
    assert any("approx" in p for p in problems)
    assert any("duplicate" in p for p in problems)


def test_gate_evaluator_defers_on_default():
    policy = load_policy(str(EXAMPLE))
    evaluator = policy.as_gate_evaluator(defer_on_default=True)
    # an explicit match returns a Decision
    assert evaluator({"action": "read.logs", "params": {}}) is not None
    # an unmatched directive returns None so a host gate can decide
    assert evaluator({"action": "mystery", "params": {}}) is None


def test_decision_is_structurally_gate_compatible():
    # agentledger's gate uses .allowed, .rule, .reason, .as_dict() via duck typing
    policy = load_policy(str(EXAMPLE))
    d = policy.evaluate({"action": "read.logs", "params": {}})
    assert hasattr(d, "allowed") and hasattr(d, "rule") and hasattr(d, "reason")
    assert set(d.as_dict()) >= {"allowed", "rule", "reason"}

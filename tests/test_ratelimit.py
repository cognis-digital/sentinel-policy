"""Tests for the sliding-window rate limiter."""
import pytest

from sentinel_policy import InMemoryStore, RateLimiter, key_from_directive


def test_within_limit_then_over():
    clock = iter([0, 1, 2, 3]).__next__
    rl = RateLimiter(limit=2, window=10, clock=clock)
    assert rl.check("k").allowed
    assert rl.check("k").allowed
    v = rl.check("k")
    assert not v.allowed
    assert v.count == 3
    assert v.retry_after == 10


def test_window_slides():
    times = iter([0, 1, 11, 12]).__next__
    rl = RateLimiter(limit=1, window=10, clock=times)
    assert rl.check("k").allowed          # t=0
    assert not rl.check("k").allowed      # t=1, still 2 in window
    assert rl.check("k").allowed          # t=11, first event evicted


def test_keys_are_independent():
    clock = iter([0, 0, 0]).__next__
    rl = RateLimiter(limit=1, window=10, clock=clock)
    assert rl.check("a").allowed
    assert rl.check("b").allowed          # different key, own budget


def test_peek_does_not_consume():
    clock = iter([0, 0, 0, 0]).__next__
    rl = RateLimiter(limit=1, window=10, clock=clock)
    assert rl.peek("k") == 0
    assert rl.check("k").allowed
    assert rl.peek("k") == 1


def test_bad_construction():
    with pytest.raises(ValueError):
        RateLimiter(limit=-1, window=1)
    with pytest.raises(ValueError):
        RateLimiter(limit=1, window=0)


def test_store_reset():
    store = InMemoryStore()
    store.hit("k", 0, 10)
    assert store.count("k", 0, 10) == 1
    store.reset("k")
    assert store.count("k", 0, 10) == 0


def test_key_from_directive_template():
    d = {"actor": "alice", "action": "deploy", "params": {"env": "prod"}}
    assert key_from_directive(d, "{actor}:{action}") == "alice:deploy"
    assert key_from_directive(d, "{params.env}") == "prod"
    assert key_from_directive(d, "{missing}") == ""
    assert key_from_directive(d, "static") == "static"

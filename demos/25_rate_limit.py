"""Scenario 25 - rate limiting: a ceiling on *how often*, not just whether.

Least Authority (S2) bounds blast radius. A sliding-window `RateLimiter` adds a
frequency ceiling: even an allowed action can be throttled per actor+action. The
limiter is deterministic under an injected clock, so a decision stays auditable.
"""
from _common import banner
from sentinel_policy import RateLimiter, key_from_directive


def main() -> None:
    banner("RATE LIMIT  -  3 deploys per actor per window, then throttle")

    # deterministic clock: five bob events + alice's, one second apart
    ticks = iter([0, 1, 2, 3, 4, 5]).__next__
    limiter = RateLimiter(limit=3, window=60, clock=ticks)

    directive = {"actor": "bob", "action": "deploy", "params": {"env": "staging"}}
    key = key_from_directive(directive, "{actor}:{action}")
    print(f"\n  limiter key: {key}   (limit=3 / 60s)\n")

    results = []
    for i in range(5):
        v = limiter.check(key)
        state = "ALLOW" if v.allowed else f"THROTTLE (retry in {v.retry_after:.0f}s)"
        print(f"  event {i + 1}: count={v.count}  -> {state}")
        results.append(v.allowed)

    assert results == [True, True, True, False, False], results

    # a different actor has an independent budget
    other = limiter.check(key_from_directive(
        {"actor": "alice", "action": "deploy"}, "{actor}:{action}"))
    print(f"\n  alice's first deploy: {'ALLOW' if other.allowed else 'THROTTLE'}")
    assert other.allowed

    print("\nThe store is pluggable (in-memory here, Redis/SQL in prod) - the")
    print("policy code never changes, only where the counters live.")


if __name__ == "__main__":
    main()

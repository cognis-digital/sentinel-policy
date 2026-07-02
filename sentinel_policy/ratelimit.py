"""Rate limiting for policy decisions — a stateful guard the engine can consult.

Least Authority (S2) and Gated Escalation (S3) both benefit from a ceiling on
*how often* an action may run, not just whether it may. A rate limiter answers
"has this key exceeded N events per W seconds?" using a sliding window.

The store is pluggable (`CounterStore`) so the same limiter works in-process for
tests and against Redis/SQL in production without touching policy code. The
default `InMemoryStore` keeps timestamps in a dict and is perfectly deterministic
under an injected clock, which is what the tests use.

Nothing here talks to the network or spawns a thread; a limiter is just data and
a comparison, so a decision stays reproducible and auditable.
"""

from __future__ import annotations

import threading
import time as _time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict


class CounterStore:
    """Interface: record a hit at `now` and count hits within the last `window`."""

    def hit(self, key: str, now: float, window: float) -> int:  # pragma: no cover - interface
        raise NotImplementedError

    def count(self, key: str, now: float, window: float) -> int:  # pragma: no cover
        raise NotImplementedError


class InMemoryStore(CounterStore):
    """A sliding-window store backed by per-key deques of timestamps."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _evict(self, dq: "Deque[float]", now: float, window: float) -> None:
        cutoff = now - window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def count(self, key: str, now: float, window: float) -> int:
        with self._lock:
            dq = self._events[key]
            self._evict(dq, now, window)
            return len(dq)

    def hit(self, key: str, now: float, window: float) -> int:
        with self._lock:
            dq = self._events[key]
            self._evict(dq, now, window)
            dq.append(now)
            return len(dq)

    def reset(self, key: "str | None" = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


@dataclass(frozen=True)
class RateVerdict:
    allowed: bool
    key: str
    limit: int
    window: float
    count: int          # count *including* this event
    retry_after: float  # seconds until the window has room again (0 if allowed)


class RateLimiter:
    """Sliding-window rate limiter.

    >>> clock = iter([0, 1, 2, 3]).__next__
    >>> rl = RateLimiter(limit=2, window=10, clock=clock)
    >>> rl.check("k").allowed, rl.check("k").allowed, rl.check("k").allowed
    (True, True, False)
    """

    def __init__(self, limit: int, window: float,
                 store: "CounterStore | None" = None,
                 clock: "Callable[[], float] | None" = None) -> None:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        if window <= 0:
            raise ValueError("window must be > 0")
        self.limit = int(limit)
        self.window = float(window)
        self.store = store or InMemoryStore()
        self._clock = clock or _time.monotonic

    def peek(self, key: str) -> int:
        """Current count in the window without recording a new event."""
        return self.store.count(key, self._clock(), self.window)

    def check(self, key: str) -> RateVerdict:
        """Record an event for `key` and report whether it is within the limit.

        The event is always recorded (so bursts past the limit still show up in
        the audit trail); `allowed` reflects whether it stayed under the ceiling.
        """
        now = self._clock()
        count = self.store.hit(key, now, self.window)
        allowed = count <= self.limit
        retry = 0.0 if allowed else self.window
        return RateVerdict(allowed=allowed, key=key, limit=self.limit,
                           window=self.window, count=count, retry_after=retry)


def key_from_directive(directive: dict, template: str) -> str:
    """Render a limiter key from a directive using {dotted.path} placeholders.

    Unknown paths render as empty. Example: "{actor}:{action}" ->
    "alice:deploy". This keeps rate scopes declarative and inspectable.
    """
    from . import conditions

    out = []
    i = 0
    while i < len(template):
        ch = template[i]
        if ch == "{":
            end = template.find("}", i)
            if end == -1:
                out.append(template[i:])
                break
            path = template[i + 1:end]
            val = conditions.get_path(directive, path)
            out.append("" if val is None else str(val))
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)

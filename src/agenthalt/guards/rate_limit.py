"""Rate Limit Guard — prevent runaway agent loops and excessive function calls."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


class RateLimitConfig(BaseModel):
    """Configuration for the Rate Limit Guard.

    Attributes:
        max_calls_per_minute: Maximum calls per minute across all functions.
        max_calls_per_minute_per_function: Maximum calls per minute for any single function.
        max_calls_per_session: Maximum total calls per session.
        max_identical_calls: Maximum identical consecutive calls (same function + args).
        burst_window_seconds: Window size for burst detection.
        burst_threshold: Number of calls in burst window that triggers a block.
        cooldown_seconds: Mandatory cooldown after a burst is detected.
    """

    max_calls_per_minute: int | None = 60
    max_calls_per_minute_per_function: int | None = 20
    max_calls_per_session: int | None = None
    max_identical_calls: int = 3
    burst_window_seconds: float = 5.0
    burst_threshold: int = 10
    cooldown_seconds: float = 30.0


class CallWindow:
    """Sliding-window call tracker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._global_calls: deque[float] = deque()
        self._function_calls: dict[str, deque[float]] = {}
        self._session_counts: dict[str, int] = {}
        self._recent_calls: deque[tuple[str, str]] = deque(maxlen=50)  # (func, args_hash)
        self._cooldown_until: float = 0.0

    def record(self, ctx: CallContext) -> None:
        now = time.time()
        with self._lock:
            self._global_calls.append(now)
            fn_calls = self._function_calls.setdefault(ctx.function_name, deque())
            fn_calls.append(now)
            if ctx.session_id:
                self._session_counts[ctx.session_id] = (
                    self._session_counts.get(ctx.session_id, 0) + 1
                )
            args_hash = str(sorted(ctx.arguments.items()))
            self._recent_calls.append((ctx.function_name, args_hash))

    def get_calls_in_window(self, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        with self._lock:
            self._prune(self._global_calls, cutoff)
            return len(self._global_calls)

    def get_function_calls_in_window(self, function_name: str, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        with self._lock:
            calls = self._function_calls.get(function_name, deque())
            self._prune(calls, cutoff)
            return len(calls)

    def get_session_count(self, session_id: str) -> int:
        with self._lock:
            return self._session_counts.get(session_id, 0)

    def count_identical_tail(self, function_name: str, args_hash: str) -> int:
        """Count how many of the most recent calls are identical to this one."""
        with self._lock:
            count = 0
            for fn, ah in reversed(self._recent_calls):
                if fn == function_name and ah == args_hash:
                    count += 1
                else:
                    break
            return count

    @property
    def in_cooldown(self) -> bool:
        return time.time() < self._cooldown_until

    @property
    def cooldown_remaining(self) -> float:
        return max(0.0, self._cooldown_until - time.time())

    def set_cooldown(self, seconds: float) -> None:
        with self._lock:
            self._cooldown_until = time.time() + seconds

    @staticmethod
    def _prune(q: deque[float], cutoff: float) -> None:
        while q and q[0] < cutoff:
            q.popleft()


class RateLimitGuard(Guard):
    """Guard that prevents runaway agent loops and excessive API calls.

    Detects and blocks:
    - Global rate limit exceeded
    - Per-function rate limit exceeded
    - Repeated identical calls (stuck in a loop)
    - Burst patterns (many calls in a very short window)
    - Session call count exceeded

    Usage:
        guard = RateLimitGuard(RateLimitConfig(
            max_calls_per_minute=30,
            max_calls_per_minute_per_function=10,
            max_identical_calls=3,
        ))
    """

    def __init__(self, config: RateLimitConfig) -> None:
        super().__init__(name="rate_limit")
        self.config = config
        self.window = CallWindow()

    async def evaluate(self, ctx: CallContext) -> Decision:
        details: dict[str, Any] = {"function": ctx.function_name}

        # Check cooldown
        if self.window.in_cooldown:
            remaining = self.window.cooldown_remaining
            return self.deny(
                f"Rate limit cooldown active: {remaining:.1f}s remaining",
                details={**details, "cooldown_remaining": remaining},
            )

        # Check global rate limit
        if self.config.max_calls_per_minute is not None:
            count = self.window.get_calls_in_window(60.0)
            if count >= self.config.max_calls_per_minute:
                return self.deny(
                    f"Global rate limit exceeded: {count}/{self.config.max_calls_per_minute} calls/min",
                    details={**details, "global_calls_per_min": count},
                )

        # Check per-function rate limit
        if self.config.max_calls_per_minute_per_function is not None:
            fn_count = self.window.get_function_calls_in_window(ctx.function_name, 60.0)
            if fn_count >= self.config.max_calls_per_minute_per_function:
                return self.deny(
                    f"Function rate limit exceeded for '{ctx.function_name}': "
                    f"{fn_count}/{self.config.max_calls_per_minute_per_function} calls/min",
                    details={**details, "function_calls_per_min": fn_count},
                )

        # Check session limit
        if self.config.max_calls_per_session is not None and ctx.session_id:
            session_count = self.window.get_session_count(ctx.session_id)
            if session_count >= self.config.max_calls_per_session:
                return self.deny(
                    f"Session call limit exceeded: {session_count}/{self.config.max_calls_per_session}",
                    details={**details, "session_calls": session_count},
                )

        # Check identical consecutive calls (loop detection)
        args_hash = str(sorted(ctx.arguments.items()))
        identical_count = self.window.count_identical_tail(ctx.function_name, args_hash)
        if identical_count >= self.config.max_identical_calls:
            return self.deny(
                f"Possible agent loop detected: '{ctx.function_name}' called {identical_count} times "
                f"with identical arguments",
                details={**details, "identical_count": identical_count},
            )

        # Check burst pattern
        burst_count = self.window.get_calls_in_window(self.config.burst_window_seconds)
        if burst_count >= self.config.burst_threshold:
            self.window.set_cooldown(self.config.cooldown_seconds)
            return self.deny(
                f"Burst detected: {burst_count} calls in {self.config.burst_window_seconds}s. "
                f"Cooldown: {self.config.cooldown_seconds}s",
                details={**details, "burst_count": burst_count},
            )

        # All checks passed
        self.window.record(ctx)
        return self.allow()

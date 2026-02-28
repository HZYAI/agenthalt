"""Tests for the Rate Limit Guard."""

import pytest

from agenthalt import RateLimitGuard, RateLimitConfig, CallContext
from agenthalt.core.decision import DecisionType


def make_ctx(fn: str = "test_func", **kwargs) -> CallContext:
    return CallContext(function_name=fn, session_id="s1", arguments=kwargs)


@pytest.mark.asyncio
async def test_allow_within_limits():
    guard = RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=100,
        max_identical_calls=10,
        burst_threshold=100,
    ))
    result = await guard.evaluate(make_ctx())
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_identical_calls():
    guard = RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=100,
        max_identical_calls=3,
        burst_threshold=100,
    ))
    # Same function + same args 3 times
    for _ in range(3):
        r = await guard.evaluate(make_ctx(query="same"))
        assert r.decision == DecisionType.ALLOW
    # 4th identical call should be blocked
    r = await guard.evaluate(make_ctx(query="same"))
    assert r.decision == DecisionType.DENY
    assert "loop" in r.reason.lower()


@pytest.mark.asyncio
async def test_different_args_not_identical():
    guard = RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=100,
        max_identical_calls=2,
        burst_threshold=100,
    ))
    r1 = await guard.evaluate(make_ctx(query="first"))
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx(query="second"))
    assert r2.decision == DecisionType.ALLOW
    r3 = await guard.evaluate(make_ctx(query="third"))
    assert r3.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_session_limit():
    guard = RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=1000,
        max_calls_per_session=5,
        max_identical_calls=100,
        burst_threshold=1000,
    ))
    for i in range(5):
        r = await guard.evaluate(make_ctx(query=f"q{i}"))
        assert r.decision == DecisionType.ALLOW
    r = await guard.evaluate(make_ctx(query="q_extra"))
    assert r.decision == DecisionType.DENY
    assert "session" in r.reason.lower()


@pytest.mark.asyncio
async def test_per_function_rate_limit():
    guard = RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=1000,
        max_calls_per_minute_per_function=3,
        max_identical_calls=100,
        burst_threshold=1000,
    ))
    for i in range(3):
        r = await guard.evaluate(make_ctx("specific_func", query=f"q{i}"))
        assert r.decision == DecisionType.ALLOW
    r = await guard.evaluate(make_ctx("specific_func", query="extra"))
    assert r.decision == DecisionType.DENY
    assert "Function rate limit" in r.reason

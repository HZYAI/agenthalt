"""Tests for the Budget Guard."""

import pytest

from agenthalt import BudgetGuard, BudgetConfig, CallContext
from agenthalt.core.decision import DecisionType


@pytest.fixture
def budget_guard() -> BudgetGuard:
    return BudgetGuard(BudgetConfig(
        max_call_cost=1.0,
        max_session_spend=5.0,
        max_daily_spend=10.0,
        warn_threshold=0.8,
        default_cost=0.1,
        cost_estimator={"expensive_call": 2.0, "cheap_call": 0.01},
    ))


def make_ctx(fn: str = "test_call", session: str = "s1", **kwargs) -> CallContext:
    return CallContext(function_name=fn, session_id=session, arguments=kwargs)


@pytest.mark.asyncio
async def test_allow_within_budget(budget_guard: BudgetGuard):
    result = await budget_guard.evaluate(make_ctx("cheap_call"))
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_over_call_cost(budget_guard: BudgetGuard):
    result = await budget_guard.evaluate(make_ctx("expensive_call"))
    assert result.decision == DecisionType.DENY
    assert "per-call limit" in result.reason


@pytest.mark.asyncio
async def test_deny_over_session_spend(budget_guard: BudgetGuard):
    guard = BudgetGuard(BudgetConfig(
        max_session_spend=0.5,
        default_cost=0.2,
    ))
    # First two calls: 0.2 + 0.2 = 0.4 (under 0.5)
    r1 = await guard.evaluate(make_ctx())
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx())
    assert r2.decision == DecisionType.ALLOW
    # Third call: 0.4 + 0.2 = 0.6 (over 0.5)
    r3 = await guard.evaluate(make_ctx())
    assert r3.decision == DecisionType.DENY
    assert "Session spend" in r3.reason


@pytest.mark.asyncio
async def test_warn_threshold_triggers_approval(budget_guard: BudgetGuard):
    guard = BudgetGuard(BudgetConfig(
        max_session_spend=1.0,
        default_cost=0.3,
        warn_threshold=0.7,
    ))
    # First two: 0.3 + 0.3 = 0.6 (60%, under 70%)
    await guard.evaluate(make_ctx())
    await guard.evaluate(make_ctx())
    # Third: 0.6 + 0.3 = 0.9 (90%, over 70% threshold)
    r = await guard.evaluate(make_ctx())
    assert r.decision == DecisionType.REQUIRE_APPROVAL


@pytest.mark.asyncio
async def test_explicit_cost_in_arguments(budget_guard: BudgetGuard):
    ctx = make_ctx(estimated_cost=0.5)
    result = await budget_guard.evaluate(ctx)
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_explicit_cost_over_limit(budget_guard: BudgetGuard):
    ctx = make_ctx(estimated_cost=5.0)
    result = await budget_guard.evaluate(ctx)
    assert result.decision == DecisionType.DENY


@pytest.mark.asyncio
async def test_daily_spend_limit():
    guard = BudgetGuard(BudgetConfig(
        max_daily_spend=0.5,
        default_cost=0.2,
    ))
    await guard.evaluate(make_ctx(session="s1"))
    await guard.evaluate(make_ctx(session="s2"))
    # 0.4 + 0.2 = 0.6 > 0.5
    r = await guard.evaluate(make_ctx(session="s3"))
    assert r.decision == DecisionType.DENY
    assert "Daily spend" in r.reason

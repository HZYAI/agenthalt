"""Tests for the Purchase Guard."""

import pytest

from agenthalt import PurchaseGuard, PurchaseConfig, CallContext
from agenthalt.core.decision import DecisionType


@pytest.fixture
def purchase_guard() -> PurchaseGuard:
    return PurchaseGuard(
        PurchaseConfig(
            max_single_purchase=100.0,
            max_daily_purchases=500.0,
            max_purchase_count_per_day=5,
            require_approval_above=50.0,
            blocked_categories=["luxury", "gambling"],
        )
    )


def make_ctx(fn: str = "purchase_item", **kwargs) -> CallContext:
    return CallContext(function_name=fn, session_id="s1", arguments=kwargs)


@pytest.mark.asyncio
async def test_allow_small_purchase(purchase_guard: PurchaseGuard):
    result = await purchase_guard.evaluate(make_ctx(amount=10.0, category="office"))
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_over_single_limit(purchase_guard: PurchaseGuard):
    result = await purchase_guard.evaluate(make_ctx(amount=200.0))
    assert result.decision == DecisionType.DENY
    assert "single-purchase limit" in result.reason


@pytest.mark.asyncio
async def test_require_approval_above_threshold(purchase_guard: PurchaseGuard):
    result = await purchase_guard.evaluate(make_ctx(amount=75.0, category="office"))
    assert result.decision == DecisionType.REQUIRE_APPROVAL


@pytest.mark.asyncio
async def test_deny_blocked_category(purchase_guard: PurchaseGuard):
    result = await purchase_guard.evaluate(make_ctx(amount=10.0, category="gambling"))
    assert result.decision == DecisionType.DENY
    assert "blocked" in result.reason


@pytest.mark.asyncio
async def test_should_apply_only_to_purchase_functions(purchase_guard: PurchaseGuard):
    ctx = CallContext(function_name="read_data", arguments={"amount": 999.0})
    assert not purchase_guard.should_apply(ctx)


@pytest.mark.asyncio
async def test_should_apply_to_purchase_functions(purchase_guard: PurchaseGuard):
    for fn in ["purchase_item", "buy_stuff", "make_payment", "checkout"]:
        ctx = CallContext(function_name=fn, arguments={})
        assert purchase_guard.should_apply(ctx), f"should_apply failed for {fn}"


@pytest.mark.asyncio
async def test_require_approval_when_amount_missing(purchase_guard: PurchaseGuard):
    result = await purchase_guard.evaluate(make_ctx())
    assert result.decision == DecisionType.REQUIRE_APPROVAL
    assert "Cannot determine" in result.reason


@pytest.mark.asyncio
async def test_daily_count_limit(purchase_guard: PurchaseGuard):
    for i in range(5):
        r = await purchase_guard.evaluate(make_ctx(amount=5.0, category="office"))
        assert r.decision == DecisionType.ALLOW, f"Call {i} failed"
    # 6th purchase should be denied
    r = await purchase_guard.evaluate(make_ctx(amount=5.0, category="office"))
    assert r.decision == DecisionType.DENY
    assert "count" in r.reason.lower()


@pytest.mark.asyncio
async def test_allowed_categories_whitelist():
    guard = PurchaseGuard(
        PurchaseConfig(
            allowed_categories=["office", "software"],
        )
    )
    r1 = await guard.evaluate(make_ctx(amount=10.0, category="office"))
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx(amount=10.0, category="food"))
    assert r2.decision == DecisionType.DENY

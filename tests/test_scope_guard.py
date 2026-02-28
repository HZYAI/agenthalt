"""Tests for the Scope Guard."""

import pytest

from agenthalt import ScopeGuard, ScopeConfig, CallContext
from agenthalt.core.decision import DecisionType


def make_ctx(fn: str, agent_id: str | None = None) -> CallContext:
    return CallContext(function_name=fn, arguments={}, agent_id=agent_id)


@pytest.mark.asyncio
async def test_allow_when_no_restrictions():
    guard = ScopeGuard(ScopeConfig())
    result = await guard.evaluate(make_ctx("anything"))
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_blacklisted_function():
    guard = ScopeGuard(ScopeConfig(deny_functions=["drop_*", "delete_*"]))
    r1 = await guard.evaluate(make_ctx("drop_table"))
    assert r1.decision == DecisionType.DENY
    r2 = await guard.evaluate(make_ctx("delete_user"))
    assert r2.decision == DecisionType.DENY
    r3 = await guard.evaluate(make_ctx("read_user"))
    assert r3.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_whitelist_mode():
    guard = ScopeGuard(ScopeConfig(allow_functions=["get_*", "list_*", "search_*"]))
    r1 = await guard.evaluate(make_ctx("get_users"))
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx("delete_user"))
    assert r2.decision == DecisionType.DENY
    assert "not in the allow list" in r2.reason


@pytest.mark.asyncio
async def test_require_approval_functions():
    guard = ScopeGuard(ScopeConfig(require_approval_functions=["send_email", "post_*"]))
    r1 = await guard.evaluate(make_ctx("send_email"))
    assert r1.decision == DecisionType.REQUIRE_APPROVAL
    r2 = await guard.evaluate(make_ctx("post_tweet"))
    assert r2.decision == DecisionType.REQUIRE_APPROVAL
    r3 = await guard.evaluate(make_ctx("read_email"))
    assert r3.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_read_only_mode():
    guard = ScopeGuard(ScopeConfig(read_only_mode=True))
    r1 = await guard.evaluate(make_ctx("get_users"))
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx("list_items"))
    assert r2.decision == DecisionType.ALLOW
    r3 = await guard.evaluate(make_ctx("delete_user"))
    assert r3.decision == DecisionType.DENY
    assert "read-only" in r3.reason.lower()


@pytest.mark.asyncio
async def test_per_agent_deny():
    guard = ScopeGuard(ScopeConfig(
        deny_by_agent={"untrusted_agent": ["send_*", "delete_*"]},
    ))
    r1 = await guard.evaluate(make_ctx("send_email", agent_id="untrusted_agent"))
    assert r1.decision == DecisionType.DENY
    r2 = await guard.evaluate(make_ctx("send_email", agent_id="trusted_agent"))
    assert r2.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_per_agent_allow():
    guard = ScopeGuard(ScopeConfig(
        allow_by_agent={"limited_agent": ["read_*", "get_*"]},
    ))
    r1 = await guard.evaluate(make_ctx("read_data", agent_id="limited_agent"))
    assert r1.decision == DecisionType.ALLOW
    r2 = await guard.evaluate(make_ctx("delete_data", agent_id="limited_agent"))
    assert r2.decision == DecisionType.DENY
    # Agent without restrictions passes
    r3 = await guard.evaluate(make_ctx("delete_data", agent_id="other_agent"))
    assert r3.decision == DecisionType.ALLOW

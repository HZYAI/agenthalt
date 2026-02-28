"""Tests for the PolicyEngine."""

import pytest

from agenthalt import PolicyEngine, CallContext
from agenthalt.core.decision import Decision, DecisionType
from agenthalt.core.guard import Guard


class AlwaysAllowGuard(Guard):
    def __init__(self):
        super().__init__(name="always_allow")

    async def evaluate(self, ctx: CallContext) -> Decision:
        return self.allow("Always allowed")


class AlwaysDenyGuard(Guard):
    def __init__(self):
        super().__init__(name="always_deny")

    async def evaluate(self, ctx: CallContext) -> Decision:
        return self.deny("Always denied")


class AlwaysApprovalGuard(Guard):
    def __init__(self):
        super().__init__(name="always_approval")

    async def evaluate(self, ctx: CallContext) -> Decision:
        return self.require_approval("Needs approval")


class ErrorGuard(Guard):
    def __init__(self):
        super().__init__(name="error_guard")

    async def evaluate(self, ctx: CallContext) -> Decision:
        raise RuntimeError("Guard crashed!")


class ScopedGuard(Guard):
    def __init__(self, applies_to: str):
        super().__init__(name=f"scoped_{applies_to}")
        self._applies_to = applies_to

    def should_apply(self, ctx: CallContext) -> bool:
        return ctx.function_name == self._applies_to

    async def evaluate(self, ctx: CallContext) -> Decision:
        return self.deny(f"Blocked for {self._applies_to}")


def make_ctx(fn: str = "test_func") -> CallContext:
    return CallContext(function_name=fn, arguments={})


@pytest.mark.asyncio
async def test_no_guards_allows():
    engine = PolicyEngine()
    result = await engine.evaluate(make_ctx())
    assert result.is_allowed


@pytest.mark.asyncio
async def test_single_allow_guard():
    engine = PolicyEngine()
    engine.add_guard(AlwaysAllowGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_allowed


@pytest.mark.asyncio
async def test_single_deny_guard():
    engine = PolicyEngine()
    engine.add_guard(AlwaysDenyGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_denied


@pytest.mark.asyncio
async def test_deny_overrides_allow():
    engine = PolicyEngine()
    engine.add_guard(AlwaysAllowGuard())
    engine.add_guard(AlwaysDenyGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_denied
    assert "Always denied" in result.denial_reasons


@pytest.mark.asyncio
async def test_approval_overrides_allow():
    engine = PolicyEngine()
    engine.add_guard(AlwaysAllowGuard())
    engine.add_guard(AlwaysApprovalGuard())
    result = await engine.evaluate(make_ctx())
    assert result.needs_approval
    assert not result.is_allowed


@pytest.mark.asyncio
async def test_deny_overrides_approval():
    engine = PolicyEngine()
    engine.add_guard(AlwaysApprovalGuard())
    engine.add_guard(AlwaysDenyGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_denied


@pytest.mark.asyncio
async def test_approved_allows_execution():
    engine = PolicyEngine()
    engine.add_guard(AlwaysApprovalGuard())
    result = await engine.evaluate(make_ctx())
    assert result.needs_approval
    result.approved = True
    assert result.is_allowed


@pytest.mark.asyncio
async def test_error_guard_fail_safe_deny():
    engine = PolicyEngine()
    engine.add_guard(ErrorGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_denied
    assert "fail-safe" in result.final_decision.reason.lower()


@pytest.mark.asyncio
async def test_scoped_guard_only_applies_to_target():
    engine = PolicyEngine()
    engine.add_guard(ScopedGuard("dangerous_func"))
    # Should not apply to other functions
    r1 = await engine.evaluate(make_ctx("safe_func"))
    assert r1.is_allowed
    # Should apply to target function
    r2 = await engine.evaluate(make_ctx("dangerous_func"))
    assert r2.is_denied


@pytest.mark.asyncio
async def test_remove_guard():
    engine = PolicyEngine()
    engine.add_guard(AlwaysDenyGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_denied
    engine.remove_guard("always_deny")
    result = await engine.evaluate(make_ctx())
    assert result.is_allowed


@pytest.mark.asyncio
async def test_disabled_guard_skipped():
    engine = PolicyEngine()
    guard = AlwaysDenyGuard()
    guard.enabled = False
    engine.add_guard(guard)
    result = await engine.evaluate(make_ctx())
    assert result.is_allowed


@pytest.mark.asyncio
async def test_pre_hook_modifies_context():
    engine = PolicyEngine()

    def add_metadata(ctx: CallContext) -> CallContext:
        new_meta = {**ctx.metadata, "hook_ran": True}
        return ctx.model_copy(update={"metadata": new_meta})

    engine.add_pre_hook(add_metadata)
    engine.add_guard(AlwaysAllowGuard())
    result = await engine.evaluate(make_ctx())
    assert result.is_allowed


@pytest.mark.asyncio
async def test_post_hook_runs():
    engine = PolicyEngine()
    engine.add_guard(AlwaysAllowGuard())
    hook_calls = []

    def track_hook(ctx, result):
        hook_calls.append((ctx.function_name, result.is_allowed))

    engine.add_post_hook(track_hook)
    await engine.evaluate(make_ctx("my_func"))
    assert len(hook_calls) == 1
    assert hook_calls[0] == ("my_func", True)


@pytest.mark.asyncio
async def test_guard_result_str():
    engine = PolicyEngine()
    engine.add_guard(AlwaysDenyGuard())
    result = await engine.evaluate(make_ctx())
    s = str(result)
    assert "deny" in s.lower()


def test_engine_repr():
    engine = PolicyEngine()
    engine.add_guard(AlwaysAllowGuard())
    engine.add_guard(AlwaysDenyGuard())
    r = repr(engine)
    assert "always_allow" in r
    assert "always_deny" in r

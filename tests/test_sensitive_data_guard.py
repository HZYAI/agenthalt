"""Tests for the Sensitive Data Guard."""

import pytest

from agenthalt import SensitiveDataGuard, SensitiveDataConfig, CallContext
from agenthalt.core.decision import DecisionType


@pytest.fixture
def guard() -> SensitiveDataGuard:
    return SensitiveDataGuard(SensitiveDataConfig(
        blocked_patterns=["ssn", "credit_card", "api_key"],
        sensitive_fields=["password", "secret", "token"],
    ))


def make_ctx(fn: str = "process_data", **kwargs) -> CallContext:
    return CallContext(function_name=fn, arguments=kwargs)


@pytest.mark.asyncio
async def test_allow_clean_data(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(query="Hello world", count=5))
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_ssn(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(data="My SSN is 123-45-6789"))
    assert result.decision == DecisionType.DENY
    assert "ssn" in result.details.get("patterns_detected", [])


@pytest.mark.asyncio
async def test_deny_credit_card(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(payment="4111-1111-1111-1111"))
    assert result.decision == DecisionType.DENY
    assert "credit_card" in result.details.get("patterns_detected", [])


@pytest.mark.asyncio
async def test_deny_api_key_pattern(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(config="sk_live_abcdefghijklmnop1234"))
    assert result.decision == DecisionType.DENY


@pytest.mark.asyncio
async def test_deny_sensitive_field_name(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(password="my_password_123"))
    assert result.decision == DecisionType.DENY
    assert "sensitive_field" in result.details.get("patterns_detected", [])


@pytest.mark.asyncio
async def test_deny_nested_sensitive_data(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(
        user={"name": "John", "ssn": "123-45-6789"}
    ))
    assert result.decision == DecisionType.DENY


@pytest.mark.asyncio
async def test_redact_mode():
    guard = SensitiveDataGuard(SensitiveDataConfig(
        blocked_patterns=["ssn"],
        redact_on_modify=True,
    ))
    result = await guard.evaluate(make_ctx(data="SSN: 123-45-6789"))
    assert result.decision == DecisionType.MODIFY
    assert result.modified_arguments is not None
    assert result.modified_arguments["data"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_allow_exempt_functions():
    guard = SensitiveDataGuard(SensitiveDataConfig(
        allow_functions=["internal_auth"],
    ))
    ctx = CallContext(function_name="internal_auth", arguments={"password": "secret123"})
    assert not guard.should_apply(ctx)


@pytest.mark.asyncio
async def test_custom_patterns():
    guard = SensitiveDataGuard(SensitiveDataConfig(
        blocked_patterns=[],
        custom_patterns={"employee_id": r"EMP-\d{6}"},
    ))
    result = await guard.evaluate(make_ctx(data="Employee EMP-123456 record"))
    assert result.decision == DecisionType.DENY


@pytest.mark.asyncio
async def test_scan_list_arguments(guard: SensitiveDataGuard):
    result = await guard.evaluate(make_ctx(
        items=["normal text", "SSN: 123-45-6789", "more text"]
    ))
    assert result.decision == DecisionType.DENY

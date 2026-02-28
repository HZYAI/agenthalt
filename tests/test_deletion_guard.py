"""Tests for the Deletion Guard."""

import pytest

from agenthalt import DeletionGuard, DeletionConfig, CallContext
from agenthalt.core.decision import DecisionType


@pytest.fixture
def deletion_guard() -> DeletionGuard:
    return DeletionGuard(
        DeletionConfig(
            allow_patterns=["temp_*", "draft_*", "cache_*"],
            deny_patterns=["*_production", "*_backup"],
            protected_resources=["inbox", "sent", "important"],
            require_approval_always=False,
            max_bulk_delete=5,
            max_deletions_per_day=20,
        )
    )


def make_ctx(fn: str = "delete_file", session: str = "s1", **kwargs) -> CallContext:
    return CallContext(function_name=fn, session_id=session, arguments=kwargs)


@pytest.mark.asyncio
async def test_allow_matching_pattern(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(make_ctx(resource_id="temp_file_001"))
    assert result.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_deny_protected_resource(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(make_ctx(resource_id="inbox"))
    assert result.decision == DecisionType.DENY
    assert "protected" in result.reason.lower()


@pytest.mark.asyncio
async def test_deny_deny_pattern(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(make_ctx(resource_id="db_production"))
    assert result.decision == DecisionType.DENY
    assert "deny pattern" in result.reason.lower()


@pytest.mark.asyncio
async def test_deny_not_in_allow_list(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(make_ctx(resource_id="important_document"))
    assert result.decision == DecisionType.DENY
    assert "does not match any allow pattern" in result.reason.lower()


@pytest.mark.asyncio
async def test_deny_bulk_over_limit(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(
        make_ctx(resource_ids=["temp_1", "temp_2", "temp_3", "temp_4", "temp_5", "temp_6"])
    )
    assert result.decision == DecisionType.DENY
    assert "bulk" in result.reason.lower()


@pytest.mark.asyncio
async def test_require_approval_when_no_resource_id(deletion_guard: DeletionGuard):
    result = await deletion_guard.evaluate(make_ctx())
    assert result.decision == DecisionType.REQUIRE_APPROVAL


@pytest.mark.asyncio
async def test_should_apply_only_to_deletion_functions(deletion_guard: DeletionGuard):
    assert deletion_guard.should_apply(CallContext(function_name="delete_file", arguments={}))
    assert deletion_guard.should_apply(CallContext(function_name="remove_item", arguments={}))
    assert not deletion_guard.should_apply(CallContext(function_name="read_file", arguments={}))
    assert not deletion_guard.should_apply(CallContext(function_name="create_doc", arguments={}))


@pytest.mark.asyncio
async def test_require_approval_always():
    guard = DeletionGuard(DeletionConfig(require_approval_always=True))
    result = await guard.evaluate(make_ctx(resource_id="anything"))
    assert result.decision == DecisionType.REQUIRE_APPROVAL


@pytest.mark.asyncio
async def test_soft_delete_only():
    guard = DeletionGuard(DeletionConfig(soft_delete_only=True))
    # Normal delete should be fine
    r1 = await guard.evaluate(make_ctx(resource_id="file_1"))
    assert r1.decision != DecisionType.DENY or "Hard" not in r1.reason
    # Hard delete should be blocked
    r2 = await guard.evaluate(make_ctx(fn="hard_delete", resource_id="file_1"))
    assert r2.decision == DecisionType.DENY
    assert "soft delete" in r2.reason.lower()


@pytest.mark.asyncio
async def test_alternative_id_fields():
    guard = DeletionGuard(DeletionConfig(allow_patterns=["*"]))
    # Test email_id field
    r = await guard.evaluate(make_ctx(email_id="msg_123"))
    assert r.decision == DecisionType.ALLOW
    # Test document_id field
    r = await guard.evaluate(make_ctx(document_id="doc_456"))
    assert r.decision == DecisionType.ALLOW

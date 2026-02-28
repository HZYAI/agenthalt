"""AgentHalt — Quick Start Example

Demonstrates how to set up guards to prevent:
1. Overspending on API calls
2. Unauthorized purchases
3. Unsafe document deletions
4. Agent runaway loops
"""

import asyncio

from agenthalt import (
    PolicyEngine,
    CallContext,
    BudgetGuard,
    BudgetConfig,
    PurchaseGuard,
    PurchaseConfig,
    DeletionGuard,
    DeletionConfig,
    RateLimitGuard,
    RateLimitConfig,
    ScopeGuard,
    ScopeConfig,
    AuditLogger,
)
from agenthalt.audit.logger import LoggingSink


async def main() -> None:
    # ── 1. Create the policy engine ──────────────────────────────
    engine = PolicyEngine()

    # ── 2. Add guards ────────────────────────────────────────────

    # Prevent overspending
    engine.add_guard(BudgetGuard(BudgetConfig(
        max_daily_spend=10.0,
        max_session_spend=2.0,
        warn_threshold=0.8,
        cost_estimator={
            "gpt4_call": 0.03,
            "web_search": 0.01,
        },
    )))

    # Prevent unauthorized purchases
    engine.add_guard(PurchaseGuard(PurchaseConfig(
        max_single_purchase=100.0,
        require_approval_above=50.0,
        blocked_categories=["luxury", "gambling"],
    )))

    # Restrict deletions
    engine.add_guard(DeletionGuard(DeletionConfig(
        allow_patterns=["temp_*", "draft_*"],
        protected_resources=["inbox", "sent", "important"],
        require_approval_always=True,
        max_bulk_delete=5,
    )))

    # Prevent runaway loops
    engine.add_guard(RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=30,
        max_identical_calls=3,
    )))

    # Restrict function scope
    engine.add_guard(ScopeGuard(ScopeConfig(
        deny_functions=["drop_*", "format_*"],
        require_approval_functions=["send_email"],
    )))

    # ── 3. Set up audit logging ──────────────────────────────────
    audit = AuditLogger()
    audit.add_sink(LoggingSink())
    engine.add_post_hook(audit.create_post_hook())

    # ── 4. Evaluate some function calls ──────────────────────────

    print("=" * 60)
    print("AgentHalt — Quick Start Demo")
    print("=" * 60)

    # ✅ Allowed: normal API call within budget
    result = await engine.evaluate(CallContext(
        function_name="gpt4_call",
        arguments={"prompt": "Hello world"},
        session_id="session_1",
    ))
    print(f"\n1. GPT-4 call: {result.final_decision.decision.value}")
    assert result.is_allowed

    # ❌ Denied: trying to delete a protected resource
    result = await engine.evaluate(CallContext(
        function_name="delete_email",
        arguments={"email_id": "inbox"},
        session_id="session_1",
    ))
    print(f"2. Delete inbox: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.is_denied

    # ⚠️ Requires approval: deleting an allowed resource
    result = await engine.evaluate(CallContext(
        function_name="delete_file",
        arguments={"resource_id": "temp_cache_001"},
        session_id="session_1",
    ))
    print(f"3. Delete temp file: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.needs_approval

    # ❌ Denied: purchase over limit
    result = await engine.evaluate(CallContext(
        function_name="purchase_item",
        arguments={"amount": 200.0, "item": "Premium subscription"},
        session_id="session_1",
    ))
    print(f"4. $200 purchase: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.is_denied

    # ⚠️ Requires approval: purchase above threshold but under limit
    result = await engine.evaluate(CallContext(
        function_name="buy_supplies",
        arguments={"amount": 75.0, "category": "office"},
        session_id="session_1",
    ))
    print(f"5. $75 purchase: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.needs_approval

    # ❌ Denied: blocked function
    result = await engine.evaluate(CallContext(
        function_name="drop_table",
        arguments={"table": "users"},
        session_id="session_1",
    ))
    print(f"6. Drop table: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.is_denied

    # ⚠️ Requires approval: send_email
    result = await engine.evaluate(CallContext(
        function_name="send_email",
        arguments={"to": "user@example.com", "subject": "Hello"},
        session_id="session_1",
    ))
    print(f"7. Send email: {result.final_decision.decision.value}")
    print(f"   Reason: {result.final_decision.reason}")
    assert result.needs_approval

    # ✅ Allowed: small purchase within limits
    result = await engine.evaluate(CallContext(
        function_name="purchase_item",
        arguments={"amount": 5.0, "category": "office"},
        session_id="session_1",
    ))
    print(f"8. $5 purchase: {result.final_decision.decision.value}")
    assert result.is_allowed

    print("\n" + "=" * 60)
    print("All assertions passed!")
    print(f"Audit log entries: {len(audit.entries)}")
    print("=" * 60)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())

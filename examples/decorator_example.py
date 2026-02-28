"""AgentHalt — Decorator Example

Shows how to use the @guarded decorator to protect functions directly.
"""

import asyncio

from agenthalt import (
    PolicyEngine,
    BudgetGuard,
    BudgetConfig,
    DeletionGuard,
    DeletionConfig,
    guarded,
)
from agenthalt.decorators import GuardedCallBlocked, GuardedCallNeedsApproval

# ── Set up the engine ────────────────────────────────────────
engine = PolicyEngine()
engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=1.0, default_cost=0.05)))
engine.add_guard(DeletionGuard(DeletionConfig(
    allow_patterns=["temp_*"],
    protected_resources=["inbox"],
    require_approval_always=False,
)))


# ── Decorate your functions ─────────────────────────────────
@guarded(engine, agent_id="my_agent", session_id="session_1")
def call_api(prompt: str, model: str = "gpt-4") -> str:
    """Simulate an API call."""
    return f"Response to: {prompt}"


@guarded(engine, agent_id="my_agent")
def delete_document(resource_id: str) -> str:
    """Simulate a document deletion."""
    return f"Deleted: {resource_id}"


@guarded(engine, agent_id="my_agent")
async def async_api_call(prompt: str) -> str:
    """Simulate an async API call."""
    await asyncio.sleep(0.01)
    return f"Async response to: {prompt}"


def main() -> None:
    print("AgentHalt — Decorator Example\n")

    # ✅ This should work fine
    result = call_api("Hello world")
    print(f"1. API call result: {result}")

    # ✅ This should work (temp_ pattern is allowed)
    result = delete_document(resource_id="temp_file_001")
    print(f"2. Delete temp file: {result}")

    # ❌ This should be blocked (inbox is protected)
    try:
        delete_document(resource_id="inbox")
        print("3. Delete inbox: SHOULD NOT REACH HERE")
    except GuardedCallBlocked as e:
        print(f"3. Delete inbox: BLOCKED — {e.result.final_decision.reason}")

    # ✅ Async call
    result = asyncio.run(async_api_call("Async hello"))
    print(f"4. Async API call: {result}")

    # Test budget exhaustion — make many calls to hit the daily limit
    print("\n5. Testing budget exhaustion (20 calls at $0.05 = $1.00 limit)...")
    for i in range(25):
        try:
            call_api(f"call #{i}")
        except (GuardedCallBlocked, GuardedCallNeedsApproval) as e:
            print(f"   Call #{i}: STOPPED — {e.result.final_decision.reason}")
            break
    else:
        print("   All 25 calls succeeded (unexpected)")

    print("\nDone!")


if __name__ == "__main__":
    main()

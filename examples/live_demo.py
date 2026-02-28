"""AgentHalt Live Demo — Simulates a rogue AI agent being controlled in real-time.

Run this alongside the dashboard to see guard evaluations stream in live:

    # Terminal 1: Start the dashboard
    python -m agenthalt.dashboard.server

    # Terminal 2: Run the demo
    python examples/live_demo.py

Then open http://localhost:8550 to watch the dashboard.
"""

from __future__ import annotations

import asyncio

from agenthalt import (
    AuditLogger,
    BudgetConfig,
    BudgetGuard,
    CallContext,
    DeletionConfig,
    DeletionGuard,
    PolicyEngine,
    PurchaseConfig,
    PurchaseGuard,
    RateLimitConfig,
    RateLimitGuard,
    ScopeConfig,
    ScopeGuard,
    SensitiveDataConfig,
    SensitiveDataGuard,
)
from agenthalt.audit.logger import LoggingSink
from agenthalt.dashboard.server import create_event_listener


def build_engine() -> PolicyEngine:
    """Build a fully-configured policy engine for the demo."""
    engine = PolicyEngine()

    # Budget Guard — prevent cost overruns
    engine.add_guard(
        BudgetGuard(
            BudgetConfig(
                max_daily_spend=10.0,
                max_session_spend=2.0,
                warn_threshold=0.8,
                cost_estimator={
                    "gpt4_call": 0.03,
                    "gpt4o_call": 0.005,
                    "image_generation": 0.04,
                    "web_search": 0.01,
                    "embedding_call": 0.0001,
                },
            )
        )
    )

    # Purchase Guard — block unauthorized purchases
    engine.add_guard(
        PurchaseGuard(
            PurchaseConfig(
                max_single_purchase=100.0,
                max_daily_purchases=500.0,
                require_approval_above=50.0,
                blocked_categories=["luxury", "gambling", "weapons"],
            )
        )
    )

    # Deletion Guard — protect critical resources
    engine.add_guard(
        DeletionGuard(
            DeletionConfig(
                allow_patterns=["temp_*", "draft_*", "cache_*"],
                protected_resources=["inbox", "sent", "production_db", "user_data"],
                require_approval_always=True,
                max_bulk_delete=5,
                cooldown_seconds=2.0,
            )
        )
    )

    # Rate Limit Guard — detect stuck loops
    engine.add_guard(
        RateLimitGuard(
            RateLimitConfig(
                max_calls_per_minute=60,
                max_calls_per_minute_per_function=20,
                max_identical_calls=3,
                burst_threshold=15,
                burst_window_seconds=3.0,
                cooldown_seconds=10.0,
            )
        )
    )

    # Scope Guard — restrict dangerous functions
    engine.add_guard(
        ScopeGuard(
            ScopeConfig(
                deny_functions=["drop_*", "format_*", "shutdown_*", "rm_*"],
                require_approval_functions=["send_email", "post_to_slack", "deploy_*"],
            )
        )
    )

    # Sensitive Data Guard — block PII leakage
    engine.add_guard(
        SensitiveDataGuard(
            SensitiveDataConfig(
                blocked_patterns=["ssn", "credit_card", "api_key", "aws_key"],
                sensitive_fields=["password", "secret", "token"],
            )
        )
    )

    # Wire up dashboard events
    engine.add_event_listener(create_event_listener())

    # Audit logging
    audit = AuditLogger()
    audit.add_sink(LoggingSink())
    engine.add_post_hook(audit.create_post_hook())

    return engine


# ── Simulated Agent Actions ────────────────────────────────────────

NORMAL_ACTIONS = [
    ("gpt4_call", {"prompt": "Summarize the Q3 report", "model": "gpt-4"}),
    ("gpt4o_call", {"prompt": "Draft an email to the team", "model": "gpt-4o"}),
    ("web_search", {"query": "latest AI safety research 2025"}),
    ("embedding_call", {"text": "Customer support ticket #4521"}),
    ("get_user_profile", {"user_id": "usr_12345"}),
    ("list_documents", {"folder": "shared/reports"}),
    ("read_file", {"path": "reports/q3_summary.md"}),
    ("search_knowledge_base", {"query": "refund policy"}),
    ("gpt4o_call", {"prompt": "Analyze customer sentiment", "model": "gpt-4o"}),
    ("fetch_metrics", {"dashboard": "sales", "period": "7d"}),
]

DANGEROUS_ACTIONS = [
    # Budget burn — expensive calls
    ("image_generation", {"prompt": "Generate 50 product images", "n": 50}),
    # Unauthorized purchase
    (
        "purchase_item",
        {"amount": 250.0, "item": "Premium GPU instance", "category": "cloud"},
    ),
    # Purchase in blocked category
    ("buy_item", {"amount": 50.0, "category": "gambling", "item": "Lottery tickets"}),
    # Delete protected resource
    ("delete_email", {"email_id": "inbox"}),
    ("delete_records", {"resource_id": "production_db"}),
    # Blocked functions
    ("drop_table", {"table": "users"}),
    ("format_disk", {"drive": "/dev/sda1"}),
    ("shutdown_server", {"server": "prod-web-01"}),
    # Sensitive data leakage
    ("send_message", {"text": "My SSN is 123-45-6789", "channel": "public"}),
    ("log_data", {"config": "SECRET_KEY_DO_NOT_EXPOSE_a1b2c3d4e5f6"}),
    # Needs approval
    ("send_email", {"to": "all@company.com", "subject": "URGENT: System update"}),
    ("deploy_production", {"version": "2.1.0", "environment": "prod"}),
]

LOOP_ACTIONS = [
    ("gpt4_call", {"prompt": "What is 2+2?", "model": "gpt-4"}),
]


async def run_scenario(
    engine: PolicyEngine, name: str, actions: list, delay: float = 0.5
):
    """Run a named scenario and print results."""
    print(f"\n{'='*60}")
    print(f"  SCENARIO: {name}")
    print(f"{'='*60}")

    for fn_name, args in actions:
        ctx = CallContext(
            function_name=fn_name,
            arguments=args,
            agent_id="demo_agent",
            session_id="demo_session",
        )
        result = await engine.evaluate(ctx)

        icon = "✅" if result.is_allowed else "⏳" if result.needs_approval else "❌"
        decision = result.final_decision.decision.value
        reason = (
            result.final_decision.reason[:60] if result.final_decision.reason else ""
        )
        risk = result.max_risk_score

        print(f"  {icon} {fn_name:<30} {decision:<20} risk={risk:.2f}  {reason}")
        await asyncio.sleep(delay)


async def main():
    print("\n" + "=" * 60)
    print("  🛡️  AgentHalt — Live Demo")
    print("  Open http://localhost:8550 for the real-time dashboard")
    print("=" * 60)

    engine = build_engine()

    # Start dashboard server in background thread (Flask-SocketIO)
    try:
        import threading

        from agenthalt.dashboard.server import create_app

        flask_app, socketio = create_app(engine)

        def _run_server():
            socketio.run(
                flask_app,
                host="127.0.0.1",
                port=8550,
                debug=False,
                allow_unsafe_werkzeug=True,
                log_output=False,
            )

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()
        await asyncio.sleep(1.5)  # Let server fully start
        print("\n  📊 Dashboard running at http://127.0.0.1:8550")
    except ImportError:
        print("\n  ⚠️  Install dashboard deps: pip install flask flask-socketio")

    print("\n  👉 Open http://localhost:8550 in your browser now!")
    for i in range(10, 0, -1):
        print(f"  ⏳ Starting in {i}s — open the dashboard now...", end="\r")
        await asyncio.sleep(1)
    print("  🚀 Starting demo!                                ")

    # ── Scenario 1: Normal agent operations ──
    await run_scenario(engine, "Normal Agent Operations", NORMAL_ACTIONS, delay=0.3)

    await asyncio.sleep(2.0)  # Let rate limit window clear

    # ── Scenario 2: Agent goes rogue ──
    await run_scenario(
        engine, "Rogue Agent — Dangerous Actions", DANGEROUS_ACTIONS, delay=1.0
    )

    await asyncio.sleep(2.0)  # Let rate limit window clear

    # ── Scenario 3: Agent stuck in a loop ──
    # Use a fresh engine with only RateLimitGuard to isolate the demo
    loop_engine = PolicyEngine()
    loop_engine.add_guard(
        RateLimitGuard(
            RateLimitConfig(
                max_calls_per_minute=100,
                max_identical_calls=3,
                burst_threshold=100,
            )
        )
    )
    loop_engine.add_event_listener(create_event_listener())
    print(f"\n{'='*60}")
    print("  SCENARIO: Agent Stuck in Loop (same call repeated)")
    print(f"{'='*60}")
    for i in range(8):
        ctx = CallContext(
            function_name="gpt4_call",
            arguments={"prompt": "What is 2+2?", "model": "gpt-4"},
            agent_id="loop_agent",
            session_id="loop_session",
        )
        result = await loop_engine.evaluate(ctx)
        icon = "✅" if result.is_allowed else "❌"
        decision = result.final_decision.decision.value
        reason = (
            result.final_decision.reason[:60] if result.final_decision.reason else ""
        )
        print(f"  {icon} Call #{i+1}: gpt4_call  {decision:<20} {reason}")
        await asyncio.sleep(0.2)

    await asyncio.sleep(1.0)

    # ── Scenario 4: Budget exhaustion ──
    # Use a fresh engine with just BudgetGuard to isolate the demo
    budget_engine = PolicyEngine()
    budget_engine.add_guard(
        BudgetGuard(
            BudgetConfig(
                max_session_spend=0.15,
                warn_threshold=0.6,
                cost_estimator={"gpt4_call": 0.03},
            )
        )
    )
    budget_engine.add_event_listener(create_event_listener())
    print(f"\n{'='*60}")
    print("  SCENARIO: Budget Exhaustion (session limit $0.15)")
    print(f"{'='*60}")
    for i in range(15):
        ctx = CallContext(
            function_name="gpt4_call",
            arguments={"prompt": f"Query #{i}", "model": "gpt-4"},
            agent_id="budget_agent",
            session_id="budget_session",
        )
        result = await budget_engine.evaluate(ctx)
        if result.is_denied:
            print(f"  ❌ Call #{i+1}: DENIED — {result.final_decision.reason[:70]}")
            break
        elif result.needs_approval:
            print(
                f"  ⏳ Call #{i+1}: NEEDS APPROVAL — {result.final_decision.reason[:70]}"
            )
        else:
            print(f"  ✅ Call #{i+1}: allowed (spent ${(i+1)*0.03:.2f} so far)")
        await asyncio.sleep(0.5)

    # Summary
    print(f"\n{'='*60}")
    print("  🏁 Demo Complete!")
    print("  Dashboard: http://127.0.0.1:8550")
    print(f"{'='*60}\n")

    # Keep dashboard running
    print("  Press Ctrl+C to stop the dashboard...\n")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n  👋 Shutting down.")


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())

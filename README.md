# 🛡️ AgentHalt

**Production-grade guardrails for AI agent function calls.**

Prevent overspending, unauthorized purchases, unsafe deletions, and more — with Human-in-the-Loop (HIL) approval that lives **outside the prompt**.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](#)
[![Dashboard](https://img.shields.io/badge/Dashboard-Real--Time-6366f1.svg)](#real-time-dashboard)

> Built by [HZYAI](https://hzy.ai) — the team behind [RAGScore](https://github.com/hzyai/ragscore) (12.5K+ downloads). NVIDIA Inception · AWS Startup.

---

## Why AgentHalt?

AI agents are increasingly making real-world function calls — sending emails, making purchases, deleting documents, calling APIs. But what happens when an agent goes rogue?

**Real incidents that AgentHalt prevents:**
- 🗑️ Agent auto-deleting emails without permission
- 💸 Runaway API calls burning through $1000s in minutes
- 🛒 Agent making unauthorized purchases
- 🔄 Infinite loops calling the same tool repeatedly
- 🔑 Leaking API keys or PII through function arguments

**AgentHalt is different from prompt-based guardrails:**
- Policies are defined **in code or YAML** — not in the system prompt
- Cannot be jailbroken or prompt-injected away
- Works as middleware between the agent and tool execution
- Provides a proper Human-in-the-Loop approval flow

## Quick Start

### Installation

```bash
pip install agenthalt
```

### 30-Second Example

```python
import asyncio
from agenthalt import (
    PolicyEngine, CallContext,
    BudgetGuard, BudgetConfig,
    DeletionGuard, DeletionConfig,
    PurchaseGuard, PurchaseConfig,
)

async def main():
    # Create the engine and add guards
    engine = PolicyEngine()
    engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))
    engine.add_guard(DeletionGuard(DeletionConfig(
        allow_patterns=["temp_*", "draft_*"],
        protected_resources=["inbox", "sent"],
    )))
    engine.add_guard(PurchaseGuard(PurchaseConfig(
        max_single_purchase=100.0,
        require_approval_above=50.0,
    )))

    # Evaluate a function call before executing it
    result = await engine.evaluate(CallContext(
        function_name="delete_email",
        arguments={"email_id": "inbox"},
    ))

    if result.is_allowed:
        execute_function(...)
    elif result.needs_approval:
        # Route to human approval
        ...
    else:
        print(f"Blocked: {result.denial_reasons}")

asyncio.run(main())
```

## Built-in Guards

### 💰 Budget Guard
Prevent overspending on API calls and external services.

```python
from agenthalt import BudgetGuard, BudgetConfig

guard = BudgetGuard(BudgetConfig(
    max_call_cost=1.0,          # Max cost per individual call
    max_session_spend=5.0,      # Max spend per session
    max_daily_spend=50.0,       # Max spend per day
    max_monthly_spend=500.0,    # Max spend per month
    warn_threshold=0.8,         # Require approval at 80% of limit
    cost_estimator={            # Known costs per function
        "gpt4_call": 0.03,
        "image_generation": 0.04,
    },
))
```

### 🛒 Purchase Guard
Prevent unauthorized or excessive purchases.

```python
from agenthalt import PurchaseGuard, PurchaseConfig

guard = PurchaseGuard(PurchaseConfig(
    max_single_purchase=100.0,        # Max per transaction
    max_daily_purchases=500.0,        # Max daily total
    max_purchase_count_per_day=10,    # Max transactions per day
    require_approval_above=50.0,      # HIL above this amount
    blocked_categories=["luxury", "gambling"],
))
```

### 🗑️ Deletion Guard
Restrict document and resource deletion to preset guidelines.

```python
from agenthalt import DeletionGuard, DeletionConfig

guard = DeletionGuard(DeletionConfig(
    allow_patterns=["temp_*", "draft_*", "cache_*"],
    deny_patterns=["*_production", "*_backup"],
    protected_resources=["inbox", "sent", "important"],
    require_approval_always=True,
    max_bulk_delete=5,
    max_deletions_per_day=20,
    soft_delete_only=True,
    cooldown_seconds=5.0,
))
```

### ⏱️ Rate Limit Guard
Prevent runaway agent loops and excessive function calls.

```python
from agenthalt import RateLimitGuard, RateLimitConfig

guard = RateLimitGuard(RateLimitConfig(
    max_calls_per_minute=30,
    max_calls_per_minute_per_function=10,
    max_calls_per_session=200,
    max_identical_calls=3,       # Detect stuck loops
    burst_threshold=15,          # Calls in burst window
    burst_window_seconds=5.0,
    cooldown_seconds=30.0,       # Cooldown after burst
))
```

### 🔐 Sensitive Data Guard
Block actions involving PII, credentials, or sensitive information.

```python
from agenthalt import SensitiveDataGuard, SensitiveDataConfig

guard = SensitiveDataGuard(SensitiveDataConfig(
    blocked_patterns=["ssn", "credit_card", "api_key", "aws_key", "jwt"],
    sensitive_fields=["password", "secret", "token"],
    custom_patterns={"employee_id": r"EMP-\d{6}"},
    redact_on_modify=True,       # Redact instead of deny
))
```

### 🎯 Scope Guard
Restrict which tools/functions an agent is allowed to call.

```python
from agenthalt import ScopeGuard, ScopeConfig

# Whitelist mode
guard = ScopeGuard(ScopeConfig(
    allow_functions=["get_*", "list_*", "search_*"],
))

# Blacklist mode with per-agent overrides
guard = ScopeGuard(ScopeConfig(
    deny_functions=["drop_*", "format_*", "shutdown_*"],
    require_approval_functions=["send_email", "post_*"],
    deny_by_agent={"untrusted_agent": ["send_*", "delete_*"]},
    read_only_mode=False,
))
```

## YAML Configuration

Define all guards in a single YAML file:

```yaml
# agenthalt.yaml
guards:
  budget:
    max_daily_spend: 10.0
    warn_threshold: 0.8
    cost_estimator:
      gpt4_call: 0.03
      web_search: 0.01

  deletion:
    allow_patterns: ["temp_*", "draft_*"]
    protected_resources: ["inbox", "sent"]
    require_approval_always: true

  purchase:
    max_single_purchase: 100.0
    require_approval_above: 50.0
    blocked_categories: ["luxury", "gambling"]

  rate_limit:
    max_calls_per_minute: 30
    max_identical_calls: 3

  scope:
    deny_functions: ["drop_*", "format_*"]

  sensitive_data:
    blocked_patterns: ["ssn", "credit_card", "api_key"]
```

```python
from agenthalt.config import load_config

engine = load_config("agenthalt.yaml")
```

## Human-in-the-Loop (HIL) Approval

AgentHalt provides pluggable approval handlers:

```python
from agenthalt.hil.approval import (
    ConsoleApprovalHandler,   # Interactive CLI prompt
    CallbackApprovalHandler,  # Custom callback (Slack, webhooks, etc.)
    AutoDenyHandler,          # Auto-deny for CI/testing
)

# Console approval (development)
handler = ConsoleApprovalHandler(timeout=300.0)

# Custom approval flow (production)
async def slack_approval(request):
    # Send to Slack, wait for response
    channel_msg = await slack.post(f"Approve {request.call_context.function_name}?")
    reaction = await slack.wait_for_reaction(channel_msg, timeout=600)
    return ApprovalResponse(approved=reaction == "✅", approver="slack")

handler = CallbackApprovalHandler(slack_approval)
```

## Decorator API

Protect functions directly with the `@guarded` decorator:

```python
from agenthalt import PolicyEngine, BudgetGuard, BudgetConfig, guarded
from agenthalt.decorators import GuardedCallBlocked

engine = PolicyEngine()
engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))

@guarded(engine, agent_id="my_agent")
def call_api(prompt: str, model: str = "gpt-4") -> str:
    return openai_client.chat(prompt, model=model)

@guarded(engine)
async def search_web(query: str) -> list[str]:
    return await web_search(query)

# Calls are automatically evaluated
try:
    result = call_api("Hello world")
except GuardedCallBlocked as e:
    print(f"Blocked: {e.result.denial_reasons}")
```

## OpenAI Integration

```python
from openai import OpenAI
from agenthalt import PolicyEngine, BudgetGuard, BudgetConfig
from agenthalt.integrations.openai_adapter import OpenAIGuardedClient

engine = PolicyEngine()
engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))

client = OpenAI()
guarded = OpenAIGuardedClient(engine=engine, agent_id="assistant")

# Standard OpenAI chat completion with tools
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Delete all my emails"}],
    tools=[...],
)

# Evaluate each tool call before executing
for tool_call in response.choices[0].message.tool_calls or []:
    result = await guarded.evaluate_tool_call(tool_call)
    if result.is_allowed:
        output = execute_tool(tool_call)
    elif result.needs_approval:
        # Route to approval flow
        ...
    else:
        # Return denial to the model
        ...
```

## Audit Logging

Every guard evaluation is logged for compliance and debugging:

```python
from agenthalt import AuditLogger
from agenthalt.audit.logger import JsonFileSink, LoggingSink

audit = AuditLogger()
audit.add_sink(JsonFileSink("audit.jsonl"))     # JSON lines file
audit.add_sink(LoggingSink())                    # Python logging

# Attach to engine
engine.add_post_hook(audit.create_post_hook())

# Query audit history
denied = audit.query(decision="deny", limit=10)
for entry in denied:
    print(f"{entry.function_name}: {entry.final_decision}")
```

## Custom Guards

Create your own guards by subclassing `Guard`:

```python
from agenthalt import Guard, CallContext
from agenthalt.core.decision import Decision

class BusinessHoursGuard(Guard):
    """Only allow certain actions during business hours."""

    def __init__(self):
        super().__init__(name="business_hours")

    def should_apply(self, ctx: CallContext) -> bool:
        return ctx.function_name in ("send_email", "make_payment")

    async def evaluate(self, ctx: CallContext) -> Decision:
        import datetime
        now = datetime.datetime.now()
        if 9 <= now.hour < 17 and now.weekday() < 5:
            return self.allow("Within business hours")
        return self.require_approval(
            f"Outside business hours ({now.strftime('%A %H:%M')})",
            risk_score=0.6,
        )

engine.add_guard(BusinessHoursGuard())
```

## Real-Time Dashboard

AgentHalt includes a built-in monitoring dashboard for live demos and production monitoring:

```bash
pip install agenthalt[dashboard]
python examples/live_demo.py
# Open http://localhost:8550
```

**Dashboard features:**
- **Live event feed** — Watch guard evaluations stream in real-time via WebSocket
- **Budget gauges** — Visual spend tracking with warn/danger thresholds
- **Stats overview** — Total evaluations, allow/deny/approval counts, avg risk score
- **Guard status** — Active guards and their evaluation counts
- **Dark theme** — Professional UI built for live demos

## Architecture

```
┌─────────────┐     ┌───────────────┐     ┌──────────────┐
│   AI Agent   │────▶│   AgentHalt    │────▶│  Tool/Action  │
│  (LLM + tools)│    │  PolicyEngine  │     │  Execution    │
└─────────────┘     └───────┬───────┘     └──────────────┘
                            │
         ┌────────────────┴─────────────────┐
         │                                  │
   ┌─────┴──────┐  ┌─────────────┐  ┌─────┴──────┐
   │   Guards   │  │  HIL Flow   │  │  Dashboard  │
   ├───────────┤  │  (Approval) │  │ (Real-Time) │
   │ Budget     │  └─────────────┘  └────────────┘
   │ Purchase   │
   │ Deletion   │  ┌─────────────┐  ┌────────────┐
   │ Rate Limit │  │ Audit Logger│  │   SQLite   │
   │ Scope      │  │ (Compliance)│  │   State    │
   │ PII/Secret │  └─────────────┘  └────────────┘
   │ Custom     │
   └───────────┘
```

**Key Design Principles:**
- **Policy-as-code** — Rules defined in Python or YAML, never in prompts
- **Zero-trust default** — Guard errors result in denial (fail-safe)
- **Composable** — Stack multiple guards; most restrictive decision wins
- **Framework-agnostic** — Works with OpenAI, LangChain, CrewAI, or raw calls
- **Async-first** — Native async with sync wrappers
- **Concurrent evaluation** — All guards run in parallel for minimal latency

## Decision Priority

When multiple guards evaluate a call, the most restrictive decision wins:

```
DENY > REQUIRE_APPROVAL > MODIFY > ALLOW
```

If any guard denies, the call is blocked — regardless of other guards allowing it.

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=agenthalt

# Type checking
mypy src/agenthalt

# Linting
ruff check src/
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025 [HZYAI Pty Ltd](https://hzy.ai)

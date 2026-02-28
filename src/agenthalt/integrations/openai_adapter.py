"""OpenAI integration — wrap OpenAI function calling with AgentHalt."""

from __future__ import annotations

import json
import logging
from typing import Any

from agenthalt.core.context import CallContext
from agenthalt.core.engine import GuardResult, PolicyEngine
from agenthalt.hil.approval import ApprovalHandler, ApprovalRequest

logger = logging.getLogger("agenthalt.openai")


class OpenAIGuardedClient:
    """Wraps OpenAI tool calls with AgentHalt policy evaluation.

    Intercepts tool_calls from OpenAI chat completions and evaluates
    them against the guard engine before execution.

    Usage:
        from openai import OpenAI
        from agenthalt import PolicyEngine, BudgetGuard, BudgetConfig
        from agenthalt.integrations.openai_adapter import OpenAIGuardedClient

        engine = PolicyEngine()
        engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))

        client = OpenAI()
        guarded = OpenAIGuardedClient(engine=engine)

        # When you get tool_calls from a chat completion:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[...],
            tools=[...],
        )

        for tool_call in response.choices[0].message.tool_calls:
            result = await guarded.evaluate_tool_call(tool_call)
            if result.is_allowed:
                # Execute the tool call
                output = execute_function(tool_call.function.name, ...)
            else:
                # Handle denial
                print(result.denial_reasons)
    """

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        approval_handler: ApprovalHandler | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.engine = engine
        self.approval_handler = approval_handler
        self.agent_id = agent_id
        self.session_id = session_id

    async def evaluate_tool_call(
        self,
        tool_call: Any,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> GuardResult:
        """Evaluate an OpenAI tool_call object against the guard engine.

        Args:
            tool_call: An OpenAI ChatCompletionMessageToolCall object.
            agent_id: Override the default agent_id for this call.
            session_id: Override the default session_id for this call.

        Returns:
            GuardResult with the evaluation outcome.
        """
        # Parse the tool call
        function_name = tool_call.function.name
        try:
            arguments = json.loads(tool_call.function.arguments)
        except (json.JSONDecodeError, AttributeError):
            arguments = {}

        ctx = CallContext(
            function_name=function_name,
            arguments=arguments,
            agent_id=agent_id or self.agent_id,
            session_id=session_id or self.session_id,
            metadata={"openai_tool_call_id": tool_call.id},
        )

        result = await self.engine.evaluate(ctx)

        # Handle approval flow
        if result.needs_approval and self.approval_handler:
            request = ApprovalRequest(
                call_context=ctx,
                decisions=result.decisions,
                reason=result.final_decision.reason,
                risk_score=result.max_risk_score,
            )
            response = await self.approval_handler.request_approval(request)
            result.approved = response.approved

        return result

    def evaluate_tool_call_sync(
        self,
        tool_call: Any,
        **kwargs: Any,
    ) -> GuardResult:
        """Synchronous version of evaluate_tool_call."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.evaluate_tool_call(tool_call, **kwargs))
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, self.evaluate_tool_call(tool_call, **kwargs))
                return future.result()

    async def evaluate_function_call(
        self,
        function_name: str,
        arguments: dict[str, Any],
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> GuardResult:
        """Evaluate a raw function name + arguments (for manual integration).

        Use this when you're not using the OpenAI SDK's tool_call objects directly.
        """
        ctx = CallContext(
            function_name=function_name,
            arguments=arguments,
            agent_id=agent_id or self.agent_id,
            session_id=session_id or self.session_id,
        )

        result = await self.engine.evaluate(ctx)

        if result.needs_approval and self.approval_handler:
            request = ApprovalRequest(
                call_context=ctx,
                decisions=result.decisions,
                reason=result.final_decision.reason,
                risk_score=result.max_risk_score,
            )
            response = await self.approval_handler.request_approval(request)
            result.approved = response.approved

        return result

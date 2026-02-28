"""Policy Engine — the central orchestrator that evaluates function calls against all guards."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision, DecisionType
from agenthalt.core.guard import Guard

if TYPE_CHECKING:
    from agenthalt.hil.approval import ApprovalHandler

logger = logging.getLogger("agenthalt")


class GuardResult:
    """Aggregated result from all guards for a single function call.

    Attributes:
        decisions: List of individual guard decisions.
        final_decision: The most restrictive decision across all guards.
        approved: Whether human approval was granted (if needed).
    """

    def __init__(self, decisions: list[Decision]) -> None:
        self.decisions = decisions
        self.approved: bool = False
        self._final: Decision | None = None

    @property
    def final_decision(self) -> Decision:
        """Return the most restrictive decision (deny > require_approval > modify > allow)."""
        if self._final is not None:
            return self._final

        if not self.decisions:
            return Decision(
                decision=DecisionType.ALLOW,
                guard_name="engine",
                reason="No guards evaluated",
            )

        priority = {
            DecisionType.DENY: 0,
            DecisionType.REQUIRE_APPROVAL: 1,
            DecisionType.MODIFY: 2,
            DecisionType.ALLOW: 3,
        }
        return min(self.decisions, key=lambda d: priority[d.decision])

    @property
    def is_allowed(self) -> bool:
        """True if the call should proceed (allowed or approved)."""
        final = self.final_decision
        if final.decision == DecisionType.ALLOW:
            return True
        if final.decision == DecisionType.MODIFY:
            return True
        return final.decision == DecisionType.REQUIRE_APPROVAL and self.approved

    @property
    def is_denied(self) -> bool:
        return self.final_decision.decision == DecisionType.DENY

    @property
    def needs_approval(self) -> bool:
        return self.final_decision.decision == DecisionType.REQUIRE_APPROVAL and not self.approved

    @property
    def modified_arguments(self) -> dict[str, Any] | None:
        """Return modified arguments if any guard requested modification."""
        for d in self.decisions:
            if d.decision == DecisionType.MODIFY and d.modified_arguments:
                return d.modified_arguments
        return None

    @property
    def denial_reasons(self) -> list[str]:
        return [d.reason for d in self.decisions if d.decision == DecisionType.DENY]

    @property
    def approval_reasons(self) -> list[str]:
        return [d.reason for d in self.decisions if d.decision == DecisionType.REQUIRE_APPROVAL]

    @property
    def max_risk_score(self) -> float:
        if not self.decisions:
            return 0.0
        return max(d.risk_score for d in self.decisions)

    def __str__(self) -> str:
        final = self.final_decision
        lines = [f"GuardResult: {final.decision.value} (risk={self.max_risk_score:.2f})"]
        for d in self.decisions:
            lines.append(f"  {d}")
        return "\n".join(lines)


class PolicyEngine:
    """Central engine that registers guards and evaluates agent function calls.

    Usage:
        engine = PolicyEngine()
        engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))
        engine.add_guard(DeletionGuard(DeletionConfig(allow_patterns=["temp_*"])))

        result = await engine.evaluate(CallContext(
            function_name="delete_email",
            arguments={"email_id": "abc123"},
        ))

        if result.is_allowed:
            # proceed with the call
            ...
        elif result.needs_approval:
            # request human approval
            ...
        else:
            # blocked
            print(result.denial_reasons)
    """

    def __init__(self, *, approval_handler: ApprovalHandler | None = None) -> None:
        self._guards: list[Guard] = []
        self._pre_hooks: list[Callable[[CallContext], CallContext]] = []
        self._post_hooks: list[Callable[[CallContext, GuardResult], None]] = []
        self._approval_handler: ApprovalHandler | None = approval_handler
        self._event_listeners: list[Callable[[dict[str, Any]], None]] = []

    def add_guard(self, guard: Guard) -> PolicyEngine:
        """Register a guard. Returns self for chaining."""
        self._guards.append(guard)
        logger.info("Registered guard: %s", guard.name)
        return self

    def remove_guard(self, name: str) -> PolicyEngine:
        """Remove a guard by name. Returns self for chaining."""
        self._guards = [g for g in self._guards if g.name != name]
        return self

    def get_guard(self, name: str) -> Guard | None:
        """Get a guard by name."""
        for g in self._guards:
            if g.name == name:
                return g
        return None

    @property
    def guards(self) -> list[Guard]:
        return list(self._guards)

    def add_pre_hook(self, hook: Callable[[CallContext], CallContext]) -> PolicyEngine:
        """Add a hook that runs before guard evaluation. Can modify context."""
        self._pre_hooks.append(hook)
        return self

    def add_post_hook(self, hook: Callable[[CallContext, GuardResult], None]) -> PolicyEngine:
        """Add a hook that runs after guard evaluation. For logging, metrics, etc."""
        self._post_hooks.append(hook)
        return self

    def set_approval_handler(self, handler: ApprovalHandler) -> PolicyEngine:
        """Set the approval handler for HIL flows. Returns self for chaining."""
        self._approval_handler = handler
        return self

    def add_event_listener(self, listener: Callable[[dict[str, Any]], None]) -> PolicyEngine:
        """Add a real-time event listener (for dashboard, webhooks, etc.)."""
        self._event_listeners.append(listener)
        return self

    def _emit_event(self, event: dict[str, Any]) -> None:
        for listener in self._event_listeners:
            try:
                listener(event)
            except Exception as e:
                logger.error("Event listener error: %s", e)

    async def evaluate(self, ctx: CallContext) -> GuardResult:
        """Evaluate a function call against all registered guards.

        Guards are evaluated concurrently. The most restrictive decision wins.
        """
        # Run pre-hooks
        for hook in self._pre_hooks:
            ctx = hook(ctx)

        # Collect applicable guards
        applicable = [g for g in self._guards if g.enabled and g.should_apply(ctx)]

        if not applicable:
            logger.debug("No applicable guards for %s", ctx.function_name)
            result = GuardResult([])
            self._run_post_hooks(ctx, result)
            return result

        # Evaluate all guards concurrently
        decisions = await asyncio.gather(
            *(g.evaluate(ctx) for g in applicable),
            return_exceptions=True,
        )

        # Handle exceptions from individual guards
        valid_decisions: list[Decision] = []
        for guard, decision in zip(applicable, decisions, strict=True):
            if isinstance(decision, Exception):
                logger.error("Guard %s raised exception: %s", guard.name, decision)
                # Fail-safe: treat guard errors as denials
                valid_decisions.append(
                    Decision(
                        decision=DecisionType.DENY,
                        guard_name=guard.name,
                        reason=f"Guard error (fail-safe deny): {decision}",
                        risk_score=1.0,
                    )
                )
            else:
                valid_decisions.append(decision)

        result = GuardResult(valid_decisions)

        logger.info(
            "Evaluated %s: %s (guards=%d, risk=%.2f)",
            ctx.function_name,
            result.final_decision.decision.value,
            len(applicable),
            result.max_risk_score,
        )

        # Emit real-time event
        self._emit_event(
            {
                "type": "evaluation",
                "call_id": ctx.call_id,
                "function_name": ctx.function_name,
                "agent_id": ctx.agent_id,
                "session_id": ctx.session_id,
                "decision": result.final_decision.decision.value,
                "risk_score": result.max_risk_score,
                "reasons": [d.reason for d in valid_decisions if d.reason],
                "guard_count": len(applicable),
                "timestamp": ctx.timestamp,
            }
        )

        # Auto-route to approval handler if wired in
        if result.needs_approval and self._approval_handler:
            from agenthalt.hil.approval import ApprovalRequest

            request = ApprovalRequest(
                call_context=ctx,
                decisions=result.decisions,
                reason=result.final_decision.reason,
                risk_score=result.max_risk_score,
            )
            response = await self._approval_handler.request_approval(request)
            result.approved = response.approved
            self._emit_event(
                {
                    "type": "approval",
                    "call_id": ctx.call_id,
                    "function_name": ctx.function_name,
                    "approved": response.approved,
                    "approver": response.approver,
                    "reason": response.reason,
                }
            )

        # Run post-hooks
        self._run_post_hooks(ctx, result)

        return result

    def evaluate_sync(self, ctx: CallContext) -> GuardResult:
        """Synchronous wrapper around evaluate()."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.evaluate(ctx))
        else:
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, self.evaluate(ctx))
                return future.result()

    def _run_post_hooks(self, ctx: CallContext, result: GuardResult) -> None:
        for hook in self._post_hooks:
            try:
                hook(ctx, result)
            except Exception as e:
                logger.error("Post-hook error: %s", e)

    def __repr__(self) -> str:
        guard_names = [g.name for g in self._guards]
        return f"PolicyEngine(guards={guard_names})"

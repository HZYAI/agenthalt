"""Human-in-the-Loop (HIL) approval handlers.

Provides pluggable approval mechanisms — from simple console prompts
to webhook-based async approval flows.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Callable

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision

logger = logging.getLogger("agenthalt.hil")


class ApprovalRequest(BaseModel):
    """A request for human approval."""

    call_context: CallContext
    decisions: list[Decision]
    reason: str
    risk_score: float
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalResponse(BaseModel):
    """Response from a human approver."""

    approved: bool
    approver: str = "unknown"
    reason: str = ""
    timestamp: float = Field(default_factory=time.time)
    conditions: dict[str, Any] = Field(default_factory=dict)


class ApprovalHandler(ABC):
    """Abstract base class for approval handlers.

    Implement this to integrate with your approval workflow —
    Slack, email, web UI, CLI, etc.
    """

    @abstractmethod
    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        """Request human approval for a flagged function call.

        This method should block until a decision is made or timeout.
        """
        ...

    async def on_approved(self, request: ApprovalRequest, response: ApprovalResponse) -> None:
        """Hook called when a request is approved. Override for custom behavior."""
        logger.info(
            "Approved: %s by %s — %s",
            request.call_context.function_name,
            response.approver,
            response.reason,
        )

    async def on_denied(self, request: ApprovalRequest, response: ApprovalResponse) -> None:
        """Hook called when a request is denied. Override for custom behavior."""
        logger.info(
            "Denied: %s by %s — %s",
            request.call_context.function_name,
            response.approver,
            response.reason,
        )


class ConsoleApprovalHandler(ApprovalHandler):
    """Simple console-based approval handler for development and testing.

    Prints the approval request to stdout and waits for user input.
    """

    def __init__(self, *, timeout: float = 300.0, default_deny: bool = True) -> None:
        self.timeout = timeout
        self.default_deny = default_deny

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        print("\n" + "=" * 60)
        print("🛡️  AGENTHALT — APPROVAL REQUIRED")
        print("=" * 60)
        print(f"Function:    {request.call_context.function_name}")
        print(f"Arguments:   {json.dumps(dict(request.call_context.arguments), indent=2, default=str)}")
        print(f"Agent:       {request.call_context.agent_id or 'unknown'}")
        print(f"Session:     {request.call_context.session_id or 'unknown'}")
        print(f"Risk Score:  {request.risk_score:.2f}")
        print(f"Reason:      {request.reason}")
        print()
        for d in request.decisions:
            if d.is_blocked:
                print(f"  ⚠️  {d}")
        print()

        try:
            # Run input() in a thread to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            response_str = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: input("Approve? [y/N]: ").strip().lower()),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, EOFError):
            print("⏰ Approval timed out — defaulting to", "DENY" if self.default_deny else "ALLOW")
            return ApprovalResponse(
                approved=not self.default_deny,
                approver="console:timeout",
                reason="Approval timed out",
            )

        approved = response_str in ("y", "yes", "approve", "ok")
        reason = ""
        if not approved and response_str not in ("n", "no", "deny", "reject", ""):
            reason = response_str  # Treat unexpected input as a denial reason

        response = ApprovalResponse(
            approved=approved,
            approver="console:user",
            reason=reason or ("Approved by user" if approved else "Denied by user"),
        )

        if approved:
            await self.on_approved(request, response)
            print("✅ Approved")
        else:
            await self.on_denied(request, response)
            print("❌ Denied")

        print("=" * 60 + "\n")
        return response


class AutoDenyHandler(ApprovalHandler):
    """Automatically denies all approval requests. Useful for CI/testing."""

    def __init__(self, reason: str = "Auto-denied (no human approver configured)") -> None:
        self._reason = reason

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        logger.warning("Auto-denying: %s — %s", request.call_context.function_name, self._reason)
        return ApprovalResponse(
            approved=False,
            approver="auto_deny",
            reason=self._reason,
        )


class AutoApproveHandler(ApprovalHandler):
    """Automatically approves all requests. ONLY for testing — never use in production."""

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        logger.warning(
            "Auto-approving: %s (risk=%.2f) — THIS SHOULD NOT BE USED IN PRODUCTION",
            request.call_context.function_name,
            request.risk_score,
        )
        return ApprovalResponse(
            approved=True,
            approver="auto_approve",
            reason="Auto-approved (testing only)",
        )


class CallbackApprovalHandler(ApprovalHandler):
    """Approval handler that delegates to a callback function.

    Useful for integrating with custom approval UIs, webhooks, or message queues.

    Usage:
        async def my_approval_flow(request):
            # Send to Slack, wait for response, etc.
            return ApprovalResponse(approved=True, approver="slack:@user")

        handler = CallbackApprovalHandler(my_approval_flow)
    """

    def __init__(self, callback: Callable[[ApprovalRequest], Any]) -> None:
        self._callback = callback

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        result = self._callback(request)
        if asyncio.iscoroutine(result):
            result = await result
        if isinstance(result, ApprovalResponse):
            return result
        if isinstance(result, bool):
            return ApprovalResponse(
                approved=result,
                approver="callback",
                reason="Decided by callback",
            )
        raise TypeError(f"Callback must return ApprovalResponse or bool, got {type(result)}")

"""Base guard interface — all guards implement this."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision, DecisionType


class Guard(ABC):
    """Abstract base class for all guards.

    Subclass this to create custom guards. You must implement `evaluate`.
    Optionally override `should_apply` to skip evaluation for irrelevant calls.

    Example:
        class MyGuard(Guard):
            def __init__(self):
                super().__init__(name="my_guard")

            async def evaluate(self, ctx: CallContext) -> Decision:
                if ctx.function_name == "dangerous_thing":
                    return self.deny("This is too dangerous")
                return self.allow()
    """

    def __init__(self, name: str, *, enabled: bool = True) -> None:
        self._name = name
        self._enabled = enabled

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def should_apply(self, ctx: CallContext) -> bool:
        """Return True if this guard should evaluate the given call.

        Override this to scope a guard to specific functions or agents.
        Default: applies to all calls.
        """
        return True

    @abstractmethod
    async def evaluate(self, ctx: CallContext) -> Decision:
        """Evaluate a function call and return a decision.

        This is the main logic of the guard. Must be implemented by subclasses.
        """
        ...

    def evaluate_sync(self, ctx: CallContext) -> Decision:
        """Synchronous wrapper around evaluate()."""
        import concurrent.futures

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.evaluate(ctx))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.evaluate(ctx))
                return future.result()

    # ── Helper factories for building decisions ──────────────────────

    def allow(self, reason: str = "") -> Decision:
        return Decision(
            decision=DecisionType.ALLOW,
            guard_name=self._name,
            reason=reason,
        )

    def deny(
        self, reason: str, *, details: dict[str, Any] | None = None, risk_score: float = 1.0
    ) -> Decision:
        return Decision(
            decision=DecisionType.DENY,
            guard_name=self._name,
            reason=reason,
            details=details or {},
            risk_score=risk_score,
        )

    def require_approval(
        self, reason: str, *, details: dict[str, Any] | None = None, risk_score: float = 0.7
    ) -> Decision:
        return Decision(
            decision=DecisionType.REQUIRE_APPROVAL,
            guard_name=self._name,
            reason=reason,
            details=details or {},
            risk_score=risk_score,
        )

    def modify(
        self,
        reason: str,
        modified_arguments: dict[str, Any],
        *,
        details: dict[str, Any] | None = None,
    ) -> Decision:
        return Decision(
            decision=DecisionType.MODIFY,
            guard_name=self._name,
            reason=reason,
            modified_arguments=modified_arguments,
            details=details or {},
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self._name!r}, enabled={self._enabled})"

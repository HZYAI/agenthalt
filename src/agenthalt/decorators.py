"""Decorators for applying guards to functions directly."""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from agenthalt.core.context import CallContext
from agenthalt.core.engine import GuardResult, PolicyEngine

F = TypeVar("F", bound=Callable[..., Any])


class GuardedCallBlocked(Exception):  # noqa: N818
    """Raised when a guarded function call is blocked by a guard."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        super().__init__(str(result))


class GuardedCallNeedsApproval(Exception):  # noqa: N818
    """Raised when a guarded function call requires human approval."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        super().__init__(str(result))


def guarded(
    engine: PolicyEngine,
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    raise_on_deny: bool = True,
    raise_on_approval: bool = True,
) -> Callable[[F], F]:
    """Decorator that wraps a function with AgentHalt policy evaluation.

    When the decorated function is called, the engine evaluates all guards
    before executing. If denied, raises GuardedCallBlocked. If approval
    is needed, raises GuardedCallNeedsApproval.

    Args:
        engine: The PolicyEngine to evaluate calls against.
        agent_id: Optional agent ID to attach to all calls.
        session_id: Optional session ID to attach to all calls.
        raise_on_deny: If True, raise an exception when denied. Otherwise return None.
        raise_on_approval: If True, raise when approval is needed. Otherwise return None.

    Usage:
        engine = PolicyEngine()
        engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))

        @guarded(engine)
        def call_api(prompt: str, model: str = "gpt-4") -> str:
            # This will be evaluated by the engine before executing
            return openai.chat(prompt, model=model)

        @guarded(engine, agent_id="research_agent")
        async def search_web(query: str) -> list[str]:
            return await web_search(query)
    """

    def decorator(func: F) -> F:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Build call context from function signature
                ctx = _build_context(func, args, kwargs, agent_id=agent_id, session_id=session_id)
                result = await engine.evaluate(ctx)

                if result.is_denied:
                    if raise_on_deny:
                        raise GuardedCallBlocked(result)
                    return None

                if result.needs_approval:
                    if raise_on_approval:
                        raise GuardedCallNeedsApproval(result)
                    return None

                # If arguments were modified, apply them
                if result.modified_arguments is not None:
                    kwargs.update(result.modified_arguments)

                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = _build_context(func, args, kwargs, agent_id=agent_id, session_id=session_id)
                result = engine.evaluate_sync(ctx)

                if result.is_denied:
                    if raise_on_deny:
                        raise GuardedCallBlocked(result)
                    return None

                if result.needs_approval:
                    if raise_on_approval:
                        raise GuardedCallNeedsApproval(result)
                    return None

                if result.modified_arguments is not None:
                    kwargs.update(result.modified_arguments)

                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    return decorator  # type: ignore[return-value]


def _build_context(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
) -> CallContext:
    """Build a CallContext from a function call's arguments."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    arguments = dict(bound.arguments)

    # Remove 'self' and 'cls' from arguments
    arguments.pop("self", None)
    arguments.pop("cls", None)

    return CallContext(
        function_name=func.__name__,
        arguments=arguments,
        agent_id=agent_id,
        session_id=session_id,
    )

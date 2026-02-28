"""Budget Guard — prevent overspending on API calls and external services."""

from __future__ import annotations

import time
import threading
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


class BudgetConfig(BaseModel):
    """Configuration for the Budget Guard.

    Attributes:
        max_call_cost: Maximum cost per individual call. Default: no limit.
        max_session_spend: Maximum cumulative spend per session. Default: no limit.
        max_daily_spend: Maximum cumulative spend per day. Default: no limit.
        max_monthly_spend: Maximum cumulative spend per month. Default: no limit.
        cost_field: Key in arguments or metadata that contains the cost estimate.
        default_cost: Default cost to assume if no cost field is present.
        warn_threshold: Fraction of budget at which to require approval (e.g., 0.8 = 80%).
        cost_estimator: Optional mapping of function_name -> estimated cost.
    """

    max_call_cost: float | None = None
    max_session_spend: float | None = None
    max_daily_spend: float | None = None
    max_monthly_spend: float | None = None
    cost_field: str = "estimated_cost"
    default_cost: float = 0.01
    warn_threshold: float = 0.8
    cost_estimator: dict[str, float] = Field(default_factory=dict)


class SpendingTracker:
    """Thread-safe tracker for cumulative spending."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_spend: dict[str, float] = {}  # session_id -> total
        self._daily_spend: float = 0.0
        self._monthly_spend: float = 0.0
        self._daily_reset: float = self._next_day_boundary()
        self._monthly_reset: float = self._next_month_boundary()
        self._call_history: list[dict[str, Any]] = []

    @property
    def lock(self) -> threading.Lock:
        """Expose lock for atomic check-and-record in guards."""
        return self._lock

    def record_unlocked(self, cost: float, session_id: str | None = None) -> None:
        """Record spending. Caller MUST hold self.lock."""
        self._maybe_reset()
        self._daily_spend += cost
        self._monthly_spend += cost
        if session_id:
            self._session_spend[session_id] = (
                self._session_spend.get(session_id, 0.0) + cost
            )
        self._call_history.append({
            "cost": cost,
            "session_id": session_id,
            "timestamp": time.time(),
        })

    def record(self, cost: float, session_id: str | None = None) -> None:
        with self._lock:
            self.record_unlocked(cost, session_id)

    def get_session_spend(self, session_id: str) -> float:
        with self._lock:
            return self._session_spend.get(session_id, 0.0)

    def get_session_spend_unlocked(self, session_id: str) -> float:
        """Get session spend. Caller MUST hold self.lock."""
        return self._session_spend.get(session_id, 0.0)

    @property
    def daily_spend(self) -> float:
        with self._lock:
            self._maybe_reset()
            return self._daily_spend

    @property
    def monthly_spend(self) -> float:
        with self._lock:
            self._maybe_reset()
            return self._monthly_spend

    def get_daily_spend_unlocked(self) -> float:
        """Get daily spend. Caller MUST hold self.lock."""
        self._maybe_reset()
        return self._daily_spend

    def get_monthly_spend_unlocked(self) -> float:
        """Get monthly spend. Caller MUST hold self.lock."""
        self._maybe_reset()
        return self._monthly_spend

    def reset(self) -> None:
        with self._lock:
            self._session_spend.clear()
            self._daily_spend = 0.0
            self._monthly_spend = 0.0
            self._call_history.clear()

    def _maybe_reset(self) -> None:
        now = time.time()
        if now >= self._daily_reset:
            self._daily_spend = 0.0
            self._daily_reset = self._next_day_boundary()
        if now >= self._monthly_reset:
            self._monthly_spend = 0.0
            self._monthly_reset = self._next_month_boundary()

    @staticmethod
    def _next_day_boundary() -> float:
        import datetime
        tomorrow = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) + datetime.timedelta(days=1)
        return tomorrow.timestamp()

    @staticmethod
    def _next_month_boundary() -> float:
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        if now.month == 12:
            first_next = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            first_next = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
        return first_next.timestamp()


class BudgetGuard(Guard):
    """Guard that prevents overspending on API calls.

    Tracks cumulative spending per session, per day, and per month.
    Denies calls that would exceed configured budgets and requires
    approval when spend approaches the warning threshold.

    Usage:
        guard = BudgetGuard(BudgetConfig(
            max_daily_spend=10.0,
            max_session_spend=2.0,
            warn_threshold=0.8,
            cost_estimator={"gpt4_call": 0.03, "web_search": 0.01},
        ))
    """

    def __init__(self, config: BudgetConfig) -> None:
        super().__init__(name="budget")
        self.config = config
        self.tracker = SpendingTracker()

    def _estimate_cost(self, ctx: CallContext) -> float:
        """Estimate the cost of a function call."""
        # Check explicit cost in arguments
        if self.config.cost_field in ctx.arguments:
            return float(ctx.arguments[self.config.cost_field])
        # Check metadata
        if self.config.cost_field in ctx.metadata:
            return float(ctx.metadata[self.config.cost_field])
        # Check cost estimator mapping
        if ctx.function_name in self.config.cost_estimator:
            return self.config.cost_estimator[ctx.function_name]
        return self.config.default_cost

    async def evaluate(self, ctx: CallContext) -> Decision:
        cost = self._estimate_cost(ctx)
        details: dict[str, Any] = {"estimated_cost": cost}

        # Per-call limit doesn't need the lock (stateless check)
        if self.config.max_call_cost is not None and cost > self.config.max_call_cost:
            return self.deny(
                f"Call cost ${cost:.4f} exceeds per-call limit ${self.config.max_call_cost:.4f}",
                details=details,
            )

        # Atomic check-and-record under a single lock to prevent race conditions
        with self.tracker.lock:
            # Check session budget
            if self.config.max_session_spend is not None and ctx.session_id:
                session_total = self.tracker.get_session_spend_unlocked(ctx.session_id) + cost
                details["session_spend"] = session_total
                details["session_limit"] = self.config.max_session_spend
                if session_total > self.config.max_session_spend:
                    return self.deny(
                        f"Session spend ${session_total:.4f} would exceed limit ${self.config.max_session_spend:.4f}",
                        details=details,
                    )
                if session_total > self.config.max_session_spend * self.config.warn_threshold:
                    return self.require_approval(
                        f"Session spend ${session_total:.4f} approaching limit ${self.config.max_session_spend:.4f} "
                        f"({session_total / self.config.max_session_spend:.0%})",
                        details=details,
                        risk_score=session_total / self.config.max_session_spend,
                    )

            # Check daily budget
            if self.config.max_daily_spend is not None:
                daily_total = self.tracker.get_daily_spend_unlocked() + cost
                details["daily_spend"] = daily_total
                details["daily_limit"] = self.config.max_daily_spend
                if daily_total > self.config.max_daily_spend:
                    return self.deny(
                        f"Daily spend ${daily_total:.4f} would exceed limit ${self.config.max_daily_spend:.4f}",
                        details=details,
                    )
                if daily_total > self.config.max_daily_spend * self.config.warn_threshold:
                    return self.require_approval(
                        f"Daily spend ${daily_total:.4f} approaching limit ${self.config.max_daily_spend:.4f} "
                        f"({daily_total / self.config.max_daily_spend:.0%})",
                        details=details,
                        risk_score=daily_total / self.config.max_daily_spend,
                    )

            # Check monthly budget
            if self.config.max_monthly_spend is not None:
                monthly_total = self.tracker.get_monthly_spend_unlocked() + cost
                details["monthly_spend"] = monthly_total
                details["monthly_limit"] = self.config.max_monthly_spend
                if monthly_total > self.config.max_monthly_spend:
                    return self.deny(
                        f"Monthly spend ${monthly_total:.4f} would exceed limit ${self.config.max_monthly_spend:.4f}",
                        details=details,
                    )

            # All checks passed — record atomically while still holding the lock
            self.tracker.record_unlocked(cost, session_id=ctx.session_id)

        return self.allow(f"Budget OK (cost: ${cost:.4f})")

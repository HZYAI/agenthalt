"""Purchase Guard — prevent unauthorized or excessive purchases."""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


class PurchaseConfig(BaseModel):
    """Configuration for the Purchase Guard.

    Attributes:
        max_single_purchase: Maximum amount for a single purchase.
        max_daily_purchases: Maximum total purchase amount per day.
        max_purchase_count_per_day: Maximum number of purchases per day.
        require_approval_above: Require human approval for purchases above this amount.
        blocked_categories: Categories of items that cannot be purchased.
        allowed_categories: If set, only these categories are allowed (whitelist mode).
        amount_field: Key in arguments that contains the purchase amount.
        category_field: Key in arguments that contains the purchase category.
        currency: Expected currency code for validation.
        purchase_functions: Function names that represent purchase actions.
    """

    max_single_purchase: float | None = None
    max_daily_purchases: float | None = None
    max_purchase_count_per_day: int | None = None
    require_approval_above: float | None = None
    blocked_categories: list[str] = Field(default_factory=list)
    allowed_categories: list[str] = Field(default_factory=list)
    amount_field: str = "amount"
    category_field: str = "category"
    currency: str = "USD"
    purchase_functions: list[str] = Field(
        default_factory=lambda: [
            "purchase", "buy", "order", "checkout", "make_payment",
            "place_order", "subscribe", "pay", "transfer_funds",
        ]
    )


class PurchaseTracker:
    """Thread-safe tracker for purchase history."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._daily_total: float = 0.0
        self._daily_count: int = 0
        self._reset_time: float = self._next_day()
        self._history: list[dict[str, Any]] = []

    def record(self, amount: float, ctx: CallContext) -> None:
        with self._lock:
            self._maybe_reset()
            self._daily_total += amount
            self._daily_count += 1
            self._history.append({
                "amount": amount,
                "function": ctx.function_name,
                "arguments": dict(ctx.arguments),
                "timestamp": time.time(),
            })

    @property
    def daily_total(self) -> float:
        with self._lock:
            self._maybe_reset()
            return self._daily_total

    @property
    def daily_count(self) -> int:
        with self._lock:
            self._maybe_reset()
            return self._daily_count

    def _maybe_reset(self) -> None:
        if time.time() >= self._reset_time:
            self._daily_total = 0.0
            self._daily_count = 0
            self._reset_time = self._next_day()

    @staticmethod
    def _next_day() -> float:
        import datetime
        tomorrow = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) + datetime.timedelta(days=1)
        return tomorrow.timestamp()


class PurchaseGuard(Guard):
    """Guard that prevents unauthorized or excessive purchases.

    Enforces per-transaction limits, daily spending caps, purchase count limits,
    and category restrictions.

    Usage:
        guard = PurchaseGuard(PurchaseConfig(
            max_single_purchase=100.0,
            max_daily_purchases=500.0,
            require_approval_above=50.0,
            blocked_categories=["luxury", "gambling"],
        ))
    """

    def __init__(self, config: PurchaseConfig) -> None:
        super().__init__(name="purchase")
        self.config = config
        self.tracker = PurchaseTracker()

    def should_apply(self, ctx: CallContext) -> bool:
        """Only apply to purchase-related function calls."""
        fn = ctx.function_name.lower()
        return any(pf in fn for pf in self.config.purchase_functions)

    def _extract_amount(self, ctx: CallContext) -> float | None:
        """Extract the purchase amount from arguments."""
        val = ctx.arguments.get(self.config.amount_field)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                return None
        # Try common alternative field names
        for field in ("price", "total", "cost", "value"):
            val = ctx.arguments.get(field)
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    continue
        return None

    def _extract_category(self, ctx: CallContext) -> str | None:
        """Extract the purchase category from arguments."""
        val = ctx.arguments.get(self.config.category_field)
        if val is not None:
            return str(val).lower()
        # Check in item details
        item = ctx.arguments.get("item", {})
        if isinstance(item, dict):
            return str(item.get("category", "")).lower() or None
        return None

    async def evaluate(self, ctx: CallContext) -> Decision:
        amount = self._extract_amount(ctx)
        category = self._extract_category(ctx)
        details: dict[str, Any] = {
            "function": ctx.function_name,
            "amount": amount,
            "category": category,
        }

        # If we can't determine the amount, require approval
        if amount is None:
            return self.require_approval(
                "Cannot determine purchase amount — requires human review",
                details=details,
                risk_score=0.8,
            )

        # Check category restrictions
        if category:
            if self.config.blocked_categories:
                for blocked in self.config.blocked_categories:
                    if blocked.lower() in category:
                        return self.deny(
                            f"Purchase category '{category}' is blocked",
                            details=details,
                        )
            if self.config.allowed_categories:
                if not any(allowed.lower() in category for allowed in self.config.allowed_categories):
                    return self.deny(
                        f"Purchase category '{category}' is not in allowed list",
                        details=details,
                    )

        # Check single purchase limit
        if self.config.max_single_purchase is not None and amount > self.config.max_single_purchase:
            return self.deny(
                f"Purchase ${amount:.2f} exceeds single-purchase limit ${self.config.max_single_purchase:.2f}",
                details=details,
            )

        # Check daily count limit
        if self.config.max_purchase_count_per_day is not None:
            if self.tracker.daily_count >= self.config.max_purchase_count_per_day:
                return self.deny(
                    f"Daily purchase count ({self.tracker.daily_count}) has reached limit "
                    f"({self.config.max_purchase_count_per_day})",
                    details={**details, "daily_count": self.tracker.daily_count},
                )

        # Check daily total limit
        if self.config.max_daily_purchases is not None:
            projected = self.tracker.daily_total + amount
            if projected > self.config.max_daily_purchases:
                return self.deny(
                    f"Daily purchase total ${projected:.2f} would exceed limit "
                    f"${self.config.max_daily_purchases:.2f}",
                    details={**details, "daily_total": projected},
                )

        # Check approval threshold
        if self.config.require_approval_above is not None and amount > self.config.require_approval_above:
            return self.require_approval(
                f"Purchase ${amount:.2f} exceeds approval threshold "
                f"${self.config.require_approval_above:.2f}",
                details=details,
                risk_score=min(amount / (self.config.max_single_purchase or amount * 2), 1.0),
            )

        # All checks passed — record the purchase
        self.tracker.record(amount, ctx)
        return self.allow(f"Purchase ${amount:.2f} approved")

"""Deletion Guard — restrict document/resource deletion to preset guidelines."""

from __future__ import annotations

import fnmatch
import re
import time
import threading
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


class DeletionConfig(BaseModel):
    """Configuration for the Deletion Guard.

    Attributes:
        allow_patterns: Glob patterns for resource names that CAN be deleted (whitelist).
        deny_patterns: Glob patterns for resource names that CANNOT be deleted (blacklist).
        protected_resources: Specific resource IDs that are never deletable.
        require_approval_always: If True, all deletions require human approval.
        max_deletions_per_session: Maximum number of deletions allowed per session.
        max_deletions_per_day: Maximum number of deletions allowed per day.
        max_bulk_delete: Maximum items in a single bulk delete operation.
        resource_field: Key in arguments that identifies the resource being deleted.
        soft_delete_only: If True, deny hard deletes and suggest soft delete instead.
        deletion_functions: Function names that represent deletion actions.
        cooldown_seconds: Minimum seconds between deletion calls (prevents rapid-fire).
    """

    allow_patterns: list[str] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)
    protected_resources: list[str] = Field(default_factory=list)
    require_approval_always: bool = False
    max_deletions_per_session: int | None = None
    max_deletions_per_day: int | None = None
    max_bulk_delete: int | None = 10
    resource_field: str = "resource_id"
    soft_delete_only: bool = False
    deletion_functions: list[str] = Field(
        default_factory=lambda: [
            "delete", "remove", "drop", "destroy", "purge", "erase",
            "trash", "wipe", "clear", "truncate",
        ]
    )
    cooldown_seconds: float = 0.0


class DeletionTracker:
    """Thread-safe tracker for deletion history."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_counts: dict[str, int] = {}
        self._daily_count: int = 0
        self._reset_time: float = self._next_day()
        self._last_deletion: float = 0.0
        self._history: list[dict[str, Any]] = []

    def record(self, ctx: CallContext) -> None:
        with self._lock:
            self._maybe_reset()
            self._daily_count += 1
            self._last_deletion = time.time()
            if ctx.session_id:
                self._session_counts[ctx.session_id] = (
                    self._session_counts.get(ctx.session_id, 0) + 1
                )
            self._history.append({
                "function": ctx.function_name,
                "arguments": dict(ctx.arguments),
                "timestamp": time.time(),
            })

    def get_session_count(self, session_id: str) -> int:
        with self._lock:
            return self._session_counts.get(session_id, 0)

    @property
    def daily_count(self) -> int:
        with self._lock:
            self._maybe_reset()
            return self._daily_count

    @property
    def last_deletion_time(self) -> float:
        with self._lock:
            return self._last_deletion

    def _maybe_reset(self) -> None:
        if time.time() >= self._reset_time:
            self._daily_count = 0
            self._reset_time = self._next_day()

    @staticmethod
    def _next_day() -> float:
        import datetime
        tomorrow = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) + datetime.timedelta(days=1)
        return tomorrow.timestamp()


class DeletionGuard(Guard):
    """Guard that restricts deletion of documents and resources.

    Enforces whitelist/blacklist patterns, protected resources, bulk limits,
    rate limits, and optional mandatory human approval for all deletions.

    This directly addresses incidents like agents auto-deleting emails —
    by default, no deletions are allowed unless explicitly permitted.

    Usage:
        guard = DeletionGuard(DeletionConfig(
            allow_patterns=["temp_*", "draft_*", "cache_*"],
            deny_patterns=["*_production", "*_backup"],
            protected_resources=["inbox", "sent", "important"],
            max_bulk_delete=5,
            require_approval_always=True,
        ))
    """

    def __init__(self, config: DeletionConfig) -> None:
        super().__init__(name="deletion")
        self.config = config
        self.tracker = DeletionTracker()

    def should_apply(self, ctx: CallContext) -> bool:
        """Only apply to deletion-related function calls."""
        fn = ctx.function_name.lower()
        return any(df in fn for df in self.config.deletion_functions)

    def _extract_resource_ids(self, ctx: CallContext) -> list[str]:
        """Extract resource identifier(s) from arguments."""
        ids: list[str] = []

        # Single resource
        val = ctx.arguments.get(self.config.resource_field)
        if val is not None:
            ids.append(str(val))

        # Bulk: list of IDs
        for field in ("resource_ids", "ids", "items", "targets"):
            val = ctx.arguments.get(field)
            if isinstance(val, list):
                ids.extend(str(v) for v in val)

        # Common alternative single fields
        if not ids:
            for field in ("id", "name", "path", "file", "document_id", "email_id", "record_id"):
                val = ctx.arguments.get(field)
                if val is not None:
                    ids.append(str(val))
                    break

        return ids

    def _check_pattern(self, resource_id: str) -> tuple[bool, str]:
        """Check if a resource matches allow/deny patterns.

        Returns (allowed, reason).
        """
        # Check protected resources first (highest priority)
        if resource_id in self.config.protected_resources:
            return False, f"Resource '{resource_id}' is protected and cannot be deleted"

        # Check deny patterns
        for pattern in self.config.deny_patterns:
            if fnmatch.fnmatch(resource_id, pattern):
                return False, f"Resource '{resource_id}' matches deny pattern '{pattern}'"

        # If allow_patterns are set, resource must match at least one
        if self.config.allow_patterns:
            for pattern in self.config.allow_patterns:
                if fnmatch.fnmatch(resource_id, pattern):
                    return True, f"Resource '{resource_id}' matches allow pattern '{pattern}'"
            return False, (
                f"Resource '{resource_id}' does not match any allow pattern. "
                f"Allowed: {self.config.allow_patterns}"
            )

        # No allow patterns and no deny match: allow by default
        return True, ""

    async def evaluate(self, ctx: CallContext) -> Decision:
        resource_ids = self._extract_resource_ids(ctx)
        details: dict[str, Any] = {
            "function": ctx.function_name,
            "resource_ids": resource_ids,
        }

        # Soft delete enforcement
        if self.config.soft_delete_only:
            fn = ctx.function_name.lower()
            hard_delete_indicators = ["hard", "permanent", "purge", "wipe", "destroy"]
            is_hard = any(ind in fn for ind in hard_delete_indicators)
            is_hard = is_hard or ctx.arguments.get("permanent", False)
            is_hard = is_hard or ctx.arguments.get("hard_delete", False)
            if is_hard:
                return self.deny(
                    "Hard deletes are not allowed. Use soft delete instead.",
                    details=details,
                )

        # Cooldown check
        if self.config.cooldown_seconds > 0:
            elapsed = time.time() - self.tracker.last_deletion_time
            if elapsed < self.config.cooldown_seconds:
                remaining = self.config.cooldown_seconds - elapsed
                return self.deny(
                    f"Deletion cooldown: {remaining:.1f}s remaining",
                    details={**details, "cooldown_remaining": remaining},
                )

        # Bulk delete limit
        if self.config.max_bulk_delete is not None and len(resource_ids) > self.config.max_bulk_delete:
            return self.deny(
                f"Bulk delete of {len(resource_ids)} items exceeds limit of {self.config.max_bulk_delete}",
                details=details,
            )

        # Session count limit
        if self.config.max_deletions_per_session is not None and ctx.session_id:
            session_count = self.tracker.get_session_count(ctx.session_id) + len(resource_ids)
            if session_count > self.config.max_deletions_per_session:
                return self.deny(
                    f"Session deletion count ({session_count}) would exceed limit "
                    f"({self.config.max_deletions_per_session})",
                    details={**details, "session_count": session_count},
                )

        # Daily count limit
        if self.config.max_deletions_per_day is not None:
            daily_count = self.tracker.daily_count + len(resource_ids)
            if daily_count > self.config.max_deletions_per_day:
                return self.deny(
                    f"Daily deletion count ({daily_count}) would exceed limit "
                    f"({self.config.max_deletions_per_day})",
                    details={**details, "daily_count": daily_count},
                )

        # Check each resource against patterns
        if not resource_ids:
            # Can't identify what's being deleted — require approval
            return self.require_approval(
                "Cannot identify target resource for deletion — requires human review",
                details=details,
                risk_score=0.9,
            )

        for rid in resource_ids:
            allowed, reason = self._check_pattern(rid)
            if not allowed:
                return self.deny(reason, details={**details, "blocked_resource": rid})

        # Mandatory approval for all deletions
        if self.config.require_approval_always:
            return self.require_approval(
                f"Deletion requires human approval: {resource_ids}",
                details=details,
                risk_score=0.6,
            )

        # All checks passed
        self.tracker.record(ctx)
        return self.allow(f"Deletion of {resource_ids} approved")

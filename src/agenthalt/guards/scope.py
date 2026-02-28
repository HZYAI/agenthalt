"""Scope Guard — restrict which tools/functions an agent is allowed to call."""

from __future__ import annotations

import fnmatch
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


class ScopeConfig(BaseModel):
    """Configuration for the Scope Guard.

    Uses a whitelist/blacklist approach to control which functions an agent can invoke.
    If allow_functions is set, ONLY those functions are permitted (whitelist mode).
    If deny_functions is set, those functions are blocked (blacklist mode).
    Both can be combined: whitelist is checked first, then blacklist.

    Attributes:
        allow_functions: Glob patterns for allowed function names (whitelist).
        deny_functions: Glob patterns for denied function names (blacklist).
        allow_by_agent: Per-agent allow overrides. Keys are agent_ids.
        deny_by_agent: Per-agent deny overrides. Keys are agent_ids.
        require_approval_functions: Functions that always require human approval.
        read_only_mode: If True, only allow functions matching read-only patterns.
        read_only_patterns: Patterns for read-only functions (used with read_only_mode).
    """

    allow_functions: list[str] = Field(default_factory=list)
    deny_functions: list[str] = Field(default_factory=list)
    allow_by_agent: dict[str, list[str]] = Field(default_factory=dict)
    deny_by_agent: dict[str, list[str]] = Field(default_factory=dict)
    require_approval_functions: list[str] = Field(default_factory=list)
    read_only_mode: bool = False
    read_only_patterns: list[str] = Field(
        default_factory=lambda: [
            "get_*", "read_*", "list_*", "fetch_*", "search_*",
            "query_*", "find_*", "lookup_*", "describe_*", "show_*",
        ]
    )


class ScopeGuard(Guard):
    """Guard that restricts which functions an agent is allowed to call.

    Implements a flexible allow/deny system with per-agent overrides,
    read-only mode, and mandatory approval for specific functions.

    Usage:
        # Whitelist mode: only allow specific functions
        guard = ScopeGuard(ScopeConfig(
            allow_functions=["search_*", "read_*", "get_*", "send_email"],
        ))

        # Blacklist mode: block dangerous functions
        guard = ScopeGuard(ScopeConfig(
            deny_functions=["delete_*", "drop_*", "format_*"],
            require_approval_functions=["send_email", "post_*"],
        ))

        # Read-only mode: only allow read operations
        guard = ScopeGuard(ScopeConfig(read_only_mode=True))
    """

    def __init__(self, config: ScopeConfig) -> None:
        super().__init__(name="scope")
        self.config = config

    def _matches_any(self, function_name: str, patterns: list[str]) -> bool:
        """Check if function_name matches any of the glob patterns."""
        return any(fnmatch.fnmatch(function_name, p) for p in patterns)

    async def evaluate(self, ctx: CallContext) -> Decision:
        fn = ctx.function_name
        details: dict[str, Any] = {"function": fn, "agent_id": ctx.agent_id}

        # Read-only mode check
        if self.config.read_only_mode:
            if not self._matches_any(fn, self.config.read_only_patterns):
                return self.deny(
                    f"Read-only mode: '{fn}' is not a read-only operation",
                    details=details,
                )

        # Per-agent deny check
        if ctx.agent_id and ctx.agent_id in self.config.deny_by_agent:
            agent_deny = self.config.deny_by_agent[ctx.agent_id]
            if self._matches_any(fn, agent_deny):
                return self.deny(
                    f"Agent '{ctx.agent_id}' is not allowed to call '{fn}'",
                    details=details,
                )

        # Per-agent allow check
        if ctx.agent_id and ctx.agent_id in self.config.allow_by_agent:
            agent_allow = self.config.allow_by_agent[ctx.agent_id]
            if not self._matches_any(fn, agent_allow):
                return self.deny(
                    f"Agent '{ctx.agent_id}' is not in allow list for '{fn}'",
                    details=details,
                )

        # Global deny check
        if self.config.deny_functions and self._matches_any(fn, self.config.deny_functions):
            return self.deny(
                f"Function '{fn}' is in the deny list",
                details=details,
            )

        # Global allow check (whitelist mode)
        if self.config.allow_functions and not self._matches_any(fn, self.config.allow_functions):
            return self.deny(
                f"Function '{fn}' is not in the allow list",
                details=details,
            )

        # Require approval check
        if self.config.require_approval_functions and self._matches_any(
            fn, self.config.require_approval_functions
        ):
            return self.require_approval(
                f"Function '{fn}' requires human approval",
                details=details,
                risk_score=0.6,
            )

        return self.allow()

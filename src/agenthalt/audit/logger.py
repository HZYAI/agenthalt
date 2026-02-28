"""Audit Logger — immutable record of all guard decisions for compliance and debugging."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, TextIO

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision, DecisionType

logger = logging.getLogger("agenthalt.audit")


class AuditEntry(BaseModel):
    """A single audit log entry."""

    timestamp: float = Field(default_factory=time.time)
    call_id: str
    function_name: str
    agent_id: str | None = None
    session_id: str | None = None
    arguments_summary: dict[str, str] = Field(default_factory=dict)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    final_decision: str = ""
    risk_score: float = 0.0
    approved: bool | None = None
    approver: str | None = None
    execution_allowed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_evaluation(
        cls,
        ctx: CallContext,
        decisions: list[Decision],
        *,
        approved: bool | None = None,
        approver: str | None = None,
        execution_allowed: bool = False,
    ) -> AuditEntry:
        """Create an audit entry from an evaluation result."""
        # Summarize arguments (truncate long values for the log)
        args_summary: dict[str, str] = {}
        for k, v in ctx.arguments.items():
            s = str(v)
            args_summary[k] = s[:100] + "..." if len(s) > 100 else s

        decision_dicts = [
            {
                "guard": d.guard_name,
                "decision": d.decision.value,
                "reason": d.reason,
                "risk_score": d.risk_score,
            }
            for d in decisions
        ]

        final = DecisionType.ALLOW
        max_risk = 0.0
        if decisions:
            priority = {
                DecisionType.DENY: 0,
                DecisionType.REQUIRE_APPROVAL: 1,
                DecisionType.MODIFY: 2,
                DecisionType.ALLOW: 3,
            }
            final = min(decisions, key=lambda d: priority[d.decision]).decision
            max_risk = max(d.risk_score for d in decisions)

        return cls(
            call_id=ctx.call_id,
            function_name=ctx.function_name,
            agent_id=ctx.agent_id,
            session_id=ctx.session_id,
            arguments_summary=args_summary,
            decisions=decision_dicts,
            final_decision=final.value,
            risk_score=max_risk,
            approved=approved,
            approver=approver,
            execution_allowed=execution_allowed,
            metadata=dict(ctx.metadata),
        )


class AuditSink:
    """Base class for audit log destinations."""

    def write(self, entry: AuditEntry) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class JsonFileSink(AuditSink):
    """Writes audit entries as JSON lines to a file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file: TextIO | None = None

    def _ensure_open(self) -> TextIO:
        if self._file is None or self._file.closed:
            self._file = open(self._path, "a", encoding="utf-8")
        return self._file

    def write(self, entry: AuditEntry) -> None:
        f = self._ensure_open()
        f.write(entry.model_dump_json() + "\n")

    def flush(self) -> None:
        if self._file and not self._file.closed:
            self._file.flush()

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()


class LoggingSink(AuditSink):
    """Writes audit entries to Python's logging system."""

    def __init__(self, logger_name: str = "agenthalt.audit") -> None:
        self._logger = logging.getLogger(logger_name)

    def write(self, entry: AuditEntry) -> None:
        level = logging.INFO
        if entry.final_decision == "deny":
            level = logging.WARNING
        elif entry.final_decision == "require_approval":
            level = logging.WARNING

        self._logger.log(
            level,
            "[%s] %s -> %s (risk=%.2f, allowed=%s)",
            entry.call_id[:8],
            entry.function_name,
            entry.final_decision,
            entry.risk_score,
            entry.execution_allowed,
        )


class CallbackSink(AuditSink):
    """Sends audit entries to a callback function (for webhooks, queues, etc.)."""

    def __init__(self, callback: Any) -> None:
        self._callback = callback

    def write(self, entry: AuditEntry) -> None:
        self._callback(entry)


class AuditLogger:
    """Central audit logger that dispatches entries to multiple sinks.

    Usage:
        audit = AuditLogger()
        audit.add_sink(JsonFileSink("audit.jsonl"))
        audit.add_sink(LoggingSink())

        # Called automatically by PolicyEngine when using the audit post-hook
        audit.log(ctx, decisions, execution_allowed=True)
    """

    def __init__(self) -> None:
        self._sinks: list[AuditSink] = []
        self._entries: list[AuditEntry] = []
        self._max_memory_entries: int = 10000

    def add_sink(self, sink: AuditSink) -> AuditLogger:
        """Add an audit sink. Returns self for chaining."""
        self._sinks.append(sink)
        return self

    def log(
        self,
        ctx: CallContext,
        decisions: list[Decision],
        *,
        approved: bool | None = None,
        approver: str | None = None,
        execution_allowed: bool = False,
    ) -> AuditEntry:
        """Log an audit entry and dispatch to all sinks."""
        entry = AuditEntry.from_evaluation(
            ctx,
            decisions,
            approved=approved,
            approver=approver,
            execution_allowed=execution_allowed,
        )

        # Store in memory (with cap)
        self._entries.append(entry)
        if len(self._entries) > self._max_memory_entries:
            self._entries = self._entries[-self._max_memory_entries:]

        # Dispatch to sinks
        for sink in self._sinks:
            try:
                sink.write(entry)
            except Exception as e:
                logger.error("Audit sink error: %s", e)

        return entry

    @property
    def entries(self) -> list[AuditEntry]:
        """Get in-memory audit entries."""
        return list(self._entries)

    def query(
        self,
        *,
        function_name: str | None = None,
        decision: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query in-memory audit entries with filters."""
        results = self._entries
        if function_name:
            results = [e for e in results if e.function_name == function_name]
        if decision:
            results = [e for e in results if e.final_decision == decision]
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if session_id:
            results = [e for e in results if e.session_id == session_id]
        if since:
            results = [e for e in results if e.timestamp >= since]
        return results[-limit:]

    def flush(self) -> None:
        for sink in self._sinks:
            try:
                sink.flush()
            except Exception as e:
                logger.error("Audit sink flush error: %s", e)

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception as e:
                logger.error("Audit sink close error: %s", e)

    def create_post_hook(self) -> Any:
        """Create a post-hook function for use with PolicyEngine.

        Usage:
            engine.add_post_hook(audit.create_post_hook())
        """
        from agenthalt.core.engine import GuardResult

        def hook(ctx: CallContext, result: GuardResult) -> None:
            self.log(
                ctx,
                result.decisions,
                approved=result.approved,
                execution_allowed=result.is_allowed,
            )

        return hook

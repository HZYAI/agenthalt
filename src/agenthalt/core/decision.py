"""Decision types returned by guards after evaluating a function call."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    """Possible outcomes of a guard evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    MODIFY = "modify"


class Decision(BaseModel):
    """Result of a guard evaluating a function call.

    Attributes:
        decision: The type of decision (allow, deny, require_approval, modify).
        guard_name: Name of the guard that produced this decision.
        reason: Human-readable explanation for the decision.
        details: Structured data about why the decision was made.
        modified_arguments: If decision is MODIFY, the new arguments to use.
        risk_score: Optional 0.0–1.0 risk score for the call.
    """

    decision: DecisionType
    guard_name: str
    reason: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    modified_arguments: dict[str, Any] | None = None
    risk_score: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.decision in (DecisionType.DENY, DecisionType.REQUIRE_APPROVAL)

    @property
    def needs_approval(self) -> bool:
        return self.decision == DecisionType.REQUIRE_APPROVAL

    def __str__(self) -> str:
        return f"[{self.guard_name}] {self.decision.value}: {self.reason}"

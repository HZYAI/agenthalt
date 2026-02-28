"""Policy definitions — declarative rules that guards enforce."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """What to do when a policy rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    MODIFY = "modify"
    LOG = "log"


class Policy(BaseModel):
    """A single policy rule that a guard can enforce.

    Policies are composable building blocks. Each guard can have
    multiple policies, and policies can be loaded from YAML or
    defined in code.

    Attributes:
        name: Unique name for this policy.
        description: Human-readable description.
        action: What happens when the policy triggers.
        priority: Higher priority policies are evaluated first. Default 0.
        enabled: Whether this policy is active.
        conditions: Dictionary of conditions that must be met for this policy to trigger.
        tags: Arbitrary tags for filtering/grouping policies.
    """

    name: str
    description: str = ""
    action: PolicyAction = PolicyAction.DENY
    priority: int = 0
    enabled: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class PolicySet(BaseModel):
    """An ordered collection of policies evaluated as a group.

    Evaluation order: policies sorted by priority (descending), first match wins.
    If no policy matches, the default action is used.
    """

    name: str
    policies: list[Policy] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.DENY
    description: str = ""

    def add(self, policy: Policy) -> PolicySet:
        """Return a new PolicySet with the policy added."""
        return self.model_copy(
            update={
                "policies": sorted(
                    [*self.policies, policy],
                    key=lambda p: p.priority,
                    reverse=True,
                )
            }
        )

    def remove(self, name: str) -> PolicySet:
        """Return a new PolicySet with the named policy removed."""
        return self.model_copy(update={"policies": [p for p in self.policies if p.name != name]})

    @property
    def active_policies(self) -> list[Policy]:
        """Return only enabled policies, sorted by priority descending."""
        return [p for p in self.policies if p.enabled]

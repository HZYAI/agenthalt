"""
AgentHalt — Production-grade guardrails for AI agent function calls.

Prevent overspending, unauthorized purchases, unsafe deletions, and more
with Human-in-the-Loop approval that lives outside the prompt.
"""

from agenthalt.core.decision import Decision, DecisionType
from agenthalt.core.engine import PolicyEngine
from agenthalt.core.guard import Guard
from agenthalt.core.context import CallContext
from agenthalt.guards.budget import BudgetGuard, BudgetConfig
from agenthalt.guards.purchase import PurchaseGuard, PurchaseConfig
from agenthalt.guards.deletion import DeletionGuard, DeletionConfig
from agenthalt.guards.rate_limit import RateLimitGuard, RateLimitConfig
from agenthalt.guards.sensitive_data import SensitiveDataGuard, SensitiveDataConfig
from agenthalt.guards.scope import ScopeGuard, ScopeConfig
from agenthalt.hil.approval import ApprovalHandler, ConsoleApprovalHandler
from agenthalt.audit.logger import AuditLogger, AuditEntry
from agenthalt.decorators import guarded

__version__ = "0.1.0"

__all__ = [
    # Core
    "PolicyEngine",
    "Guard",
    "Decision",
    "DecisionType",
    "CallContext",
    # Guards
    "BudgetGuard",
    "BudgetConfig",
    "PurchaseGuard",
    "PurchaseConfig",
    "DeletionGuard",
    "DeletionConfig",
    "RateLimitGuard",
    "RateLimitConfig",
    "SensitiveDataGuard",
    "SensitiveDataConfig",
    "ScopeGuard",
    "ScopeConfig",
    # HIL
    "ApprovalHandler",
    "ConsoleApprovalHandler",
    # Audit
    "AuditLogger",
    "AuditEntry",
    # Decorators
    "guarded",
]

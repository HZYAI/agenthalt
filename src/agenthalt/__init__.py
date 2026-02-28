"""
AgentHalt — Production-grade guardrails for AI agent function calls.

Prevent overspending, unauthorized purchases, unsafe deletions, and more
with Human-in-the-Loop approval that lives outside the prompt.
"""

from agenthalt.audit.logger import AuditEntry, AuditLogger
from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision, DecisionType
from agenthalt.core.engine import PolicyEngine
from agenthalt.core.guard import Guard
from agenthalt.decorators import guarded
from agenthalt.guards.budget import BudgetConfig, BudgetGuard
from agenthalt.guards.deletion import DeletionConfig, DeletionGuard
from agenthalt.guards.purchase import PurchaseConfig, PurchaseGuard
from agenthalt.guards.rate_limit import RateLimitConfig, RateLimitGuard
from agenthalt.guards.scope import ScopeConfig, ScopeGuard
from agenthalt.guards.sensitive_data import SensitiveDataConfig, SensitiveDataGuard
from agenthalt.hil.approval import ApprovalHandler, ConsoleApprovalHandler

__version__ = "0.1.1"

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

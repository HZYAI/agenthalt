"""YAML configuration loader — define guards and policies in config files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agenthalt.core.engine import PolicyEngine
from agenthalt.guards.budget import BudgetConfig, BudgetGuard
from agenthalt.guards.deletion import DeletionConfig, DeletionGuard
from agenthalt.guards.purchase import PurchaseConfig, PurchaseGuard
from agenthalt.guards.rate_limit import RateLimitConfig, RateLimitGuard
from agenthalt.guards.scope import ScopeConfig, ScopeGuard
from agenthalt.guards.sensitive_data import SensitiveDataConfig, SensitiveDataGuard

_GUARD_REGISTRY: dict[str, tuple[type, type]] = {
    "budget": (BudgetGuard, BudgetConfig),
    "purchase": (PurchaseGuard, PurchaseConfig),
    "deletion": (DeletionGuard, DeletionConfig),
    "rate_limit": (RateLimitGuard, RateLimitConfig),
    "scope": (ScopeGuard, ScopeConfig),
    "sensitive_data": (SensitiveDataGuard, SensitiveDataConfig),
}


def load_config(path: str | Path) -> PolicyEngine:
    """Load a PolicyEngine from a YAML configuration file.

    Example YAML:
        guards:
          budget:
            max_daily_spend: 10.0
            max_session_spend: 2.0
            warn_threshold: 0.8
            cost_estimator:
              gpt4_call: 0.03
              web_search: 0.01

          deletion:
            allow_patterns:
              - "temp_*"
              - "draft_*"
            protected_resources:
              - inbox
              - sent
            require_approval_always: true

          purchase:
            max_single_purchase: 100.0
            require_approval_above: 50.0
            blocked_categories:
              - luxury
              - gambling

          rate_limit:
            max_calls_per_minute: 30
            max_identical_calls: 3

          scope:
            deny_functions:
              - "drop_*"
              - "format_*"
            require_approval_functions:
              - send_email

          sensitive_data:
            blocked_patterns:
              - ssn
              - credit_card
              - api_key
    """
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid config file: expected a mapping, got {type(data)}")

    return _build_engine(data)


def load_config_from_dict(data: dict[str, Any]) -> PolicyEngine:
    """Load a PolicyEngine from a dictionary (same schema as YAML)."""
    return _build_engine(data)


def _build_engine(data: dict[str, Any]) -> PolicyEngine:
    engine = PolicyEngine()
    guards_config = data.get("guards", {})

    for guard_name, guard_config in guards_config.items():
        if guard_name not in _GUARD_REGISTRY:
            raise ValueError(
                f"Unknown guard: '{guard_name}'. Available: {list(_GUARD_REGISTRY.keys())}"
            )

        guard_cls, config_cls = _GUARD_REGISTRY[guard_name]
        config = config_cls(**(guard_config or {}))
        guard = guard_cls(config)

        # Check for enabled flag
        if guard_config and guard_config.get("enabled") is False:
            guard.enabled = False

        engine.add_guard(guard)

    return engine

"""Sensitive Data Guard — block actions involving PII, credentials, or sensitive information."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from agenthalt.core.context import CallContext
from agenthalt.core.decision import Decision
from agenthalt.core.guard import Guard


# Pre-compiled patterns for common sensitive data types
_BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "phone_us": re.compile(r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "api_key": re.compile(r"(?:sk|pk|api|key|token|secret|password)[_\-]?[a-zA-Z0-9_\-]{16,}", re.IGNORECASE),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "jwt": re.compile(r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "password_field": re.compile(r"\b(?:password|passwd|pwd|secret|token)\b", re.IGNORECASE),
}


class SensitiveDataConfig(BaseModel):
    """Configuration for the Sensitive Data Guard.

    Attributes:
        scan_arguments: Whether to scan function arguments for sensitive data.
        scan_depth: How many levels deep to scan nested arguments.
        blocked_patterns: List of builtin pattern names to block (e.g., "ssn", "credit_card").
        custom_patterns: Dictionary of custom regex patterns to scan for.
        sensitive_fields: Field names that should never be passed to agent functions.
        redact_on_modify: If True, use MODIFY to redact sensitive data instead of DENY.
        allow_functions: Functions exempt from sensitive data scanning.
    """

    scan_arguments: bool = True
    scan_depth: int = 5
    blocked_patterns: list[str] = Field(
        default_factory=lambda: ["ssn", "credit_card", "api_key", "aws_key", "jwt"]
    )
    custom_patterns: dict[str, str] = Field(default_factory=dict)
    sensitive_fields: list[str] = Field(
        default_factory=lambda: [
            "password", "secret", "token", "api_key", "private_key",
            "ssn", "credit_card", "social_security",
        ]
    )
    redact_on_modify: bool = False
    allow_functions: list[str] = Field(default_factory=list)


class SensitiveDataGuard(Guard):
    """Guard that detects and blocks exposure of sensitive data in function calls.

    Scans function arguments for PII (SSNs, credit cards), credentials
    (API keys, passwords), and other configurable sensitive patterns.

    Usage:
        guard = SensitiveDataGuard(SensitiveDataConfig(
            blocked_patterns=["ssn", "credit_card", "api_key"],
            sensitive_fields=["password", "secret"],
        ))
    """

    def __init__(self, config: SensitiveDataConfig) -> None:
        super().__init__(name="sensitive_data")
        self.config = config
        self._compiled_custom: dict[str, re.Pattern[str]] = {
            name: re.compile(pattern)
            for name, pattern in config.custom_patterns.items()
        }

    def should_apply(self, ctx: CallContext) -> bool:
        return ctx.function_name not in self.config.allow_functions

    def _get_active_patterns(self) -> dict[str, re.Pattern[str]]:
        patterns: dict[str, re.Pattern[str]] = {}
        for name in self.config.blocked_patterns:
            if name in _BUILTIN_PATTERNS:
                patterns[name] = _BUILTIN_PATTERNS[name]
        patterns.update(self._compiled_custom)
        return patterns

    def _scan_value(self, value: Any, path: str, depth: int) -> list[dict[str, str]]:
        """Recursively scan a value for sensitive data. Returns list of findings."""
        if depth <= 0:
            return []

        findings: list[dict[str, str]] = []

        if isinstance(value, str):
            patterns = self._get_active_patterns()
            for name, pattern in patterns.items():
                if pattern.search(value):
                    findings.append({
                        "pattern": name,
                        "path": path,
                        "preview": value[:50] + ("..." if len(value) > 50 else ""),
                    })
        elif isinstance(value, dict):
            for k, v in value.items():
                # Check if the field name itself is sensitive
                if any(sf in str(k).lower() for sf in self.config.sensitive_fields):
                    findings.append({
                        "pattern": "sensitive_field",
                        "path": f"{path}.{k}",
                        "preview": f"[field name '{k}' is sensitive]",
                    })
                findings.extend(self._scan_value(v, f"{path}.{k}", depth - 1))
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                findings.extend(self._scan_value(item, f"{path}[{i}]", depth - 1))

        return findings

    async def evaluate(self, ctx: CallContext) -> Decision:
        if not self.config.scan_arguments:
            return self.allow()

        findings: list[dict[str, str]] = []
        for key, value in ctx.arguments.items():
            # Check if the top-level argument key itself is sensitive
            if any(sf in str(key).lower() for sf in self.config.sensitive_fields):
                findings.append({
                    "pattern": "sensitive_field",
                    "path": key,
                    "preview": f"[field name '{key}' is sensitive]",
                })
            findings.extend(self._scan_value(value, key, self.config.scan_depth))

        # Also scan metadata
        for key, value in ctx.metadata.items():
            findings.extend(self._scan_value(value, f"metadata.{key}", self.config.scan_depth))

        if not findings:
            return self.allow()

        details = {
            "findings_count": len(findings),
            "findings": findings[:10],  # Cap to prevent huge payloads
            "patterns_detected": list({f["pattern"] for f in findings}),
        }

        if self.config.redact_on_modify:
            # Build modified arguments with sensitive data redacted
            redacted = dict(ctx.arguments)
            for finding in findings:
                path_parts = finding["path"].split(".")
                if path_parts[0] in redacted and isinstance(redacted[path_parts[0]], str):
                    redacted[path_parts[0]] = "[REDACTED]"
            return self.modify(
                f"Redacted {len(findings)} sensitive data finding(s)",
                modified_arguments=redacted,
                details=details,
            )

        pattern_names = ", ".join(sorted({f["pattern"] for f in findings}))
        return self.deny(
            f"Sensitive data detected in arguments: {pattern_names} ({len(findings)} finding(s))",
            details=details,
        )

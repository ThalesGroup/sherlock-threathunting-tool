"""Structured errors surfaced to the model.

The model never sees a technical trace: no endpoint, no service identity, no real
workspace name, no exception message from a third-party library.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    SCHEMA_INVALID = "schema_invalid"
    QUERY_REJECTED = "query_rejected"
    WINDOW_TOO_LARGE = "window_too_large"
    UNKNOWN_TARGET = "unknown_target"
    IOC_NOT_VALIDATED = "ioc_not_validated"
    IOC_UNSOURCED = "ioc_unsourced"
    EGRESS_BLOCKED = "egress_blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RATE_LIMITED = "rate_limited"
    EVIDENCE_MISSING = "evidence_missing"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    UPSTREAM_REJECTED = "upstream_rejected"


class ToolError(Exception):
    """Error destined for the model. The message must be short and actionable."""

    def __init__(self, code: ErrorCode, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.code.value, "message": self.message}
        if self.hint:
            payload["hint"] = self.hint
        return payload


class BudgetExhausted(ToolError):
    """Raised when a hunt budget is exhausted. Triggers a clean shutdown."""

    def __init__(self, budget: str, limit: int | float) -> None:
        super().__init__(
            ErrorCode.BUDGET_EXHAUSTED,
            f"Budget exhausted: {budget} (limit {limit}).",
            hint="Conclude the hunt with the material already collected.",
        )
        self.budget = budget
        self.limit = limit

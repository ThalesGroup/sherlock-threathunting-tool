"""Static analysis of UDM searches before sending to Google SecOps.

The UDM search API only exposes reads, but the neighboring language (YARA-L) is used to
define detection rules. Any rule construct is therefore rejected: search alone is
allowed, and the time window goes through the API parameters, not the query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from middleware.errors import ErrorCode, ToolError

_RULE_CONSTRUCTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\brule\s+[A-Za-z_]", re.I), "YARA-L rule definition"),
    (re.compile(r"^\s*meta\s*:", re.I | re.M), "rule `meta:` section"),
    (re.compile(r"^\s*events\s*:", re.I | re.M), "rule `events:` section"),
    (re.compile(r"^\s*match\s*:", re.I | re.M), "rule `match:` section"),
    (re.compile(r"^\s*outcome\s*:", re.I | re.M), "rule `outcome:` section"),
    (re.compile(r"^\s*condition\s*:", re.I | re.M), "rule `condition:` section"),
    (re.compile(r"[{}]"), "rule block"),
)

_MAX_QUERY_CHARS = 4_000


@dataclass(frozen=True)
class UdmPlan:
    query: str
    row_cap: int
    notes: tuple[str, ...] = ()


def validate_udm(query: str, *, row_cap: int) -> UdmPlan:
    if not query or not query.strip():
        raise ToolError(ErrorCode.QUERY_REJECTED, "Query rejected: empty query.")

    cleaned = query.strip()
    if len(cleaned) > _MAX_QUERY_CHARS:
        raise ToolError(
            ErrorCode.QUERY_REJECTED,
            f"Query rejected: length greater than {_MAX_QUERY_CHARS} characters.",
            hint="Split the search into several targeted queries.",
        )

    for pattern, label in _RULE_CONSTRUCTS:
        if pattern.search(cleaned):
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                f"Query rejected: {label} detected.",
                hint="Only UDM search is allowed, not rule definition.",
            )

    return UdmPlan(
        query=cleaned,
        row_cap=row_cap,
        notes=(f"cap of {row_cap} rows applied by the platform",),
    )


def validate_window(
    start_iso: str,
    end_iso: str,
    *,
    max_days: int,
) -> tuple[str, str]:
    """Check the requested window. The bounds go as API parameters, not in the query."""

    from datetime import datetime

    def _parse(value: str, label: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                f"{label} is not a valid ISO 8601 date.",
                hint="Expected format: 2026-07-01T00:00:00Z.",
            ) from exc
        if parsed.tzinfo is None:
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                f"{label} must carry a time zone.",
                hint="Suffix with Z for UTC.",
            )
        return parsed

    start = _parse(start_iso, "start_time")
    end = _parse(end_iso, "end_time")

    if end <= start:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            "end_time must be later than start_time.",
        )

    span_days = (end - start).total_seconds() / 86_400
    if span_days > max_days:
        raise ToolError(
            ErrorCode.WINDOW_TOO_LARGE,
            f"Requested window of {span_days:.1f} days, cap {max_days} days.",
            hint="Reduce the period or split the hunt into several windows.",
        )

    return start.isoformat(), end.isoformat()

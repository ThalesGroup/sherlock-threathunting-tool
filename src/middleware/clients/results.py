"""Common shape of the raw results returned by a SIEM, before minimization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryOutcome:
    rows: list[dict[str, Any]]
    truncated: bool = False
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def row_count(self) -> int:
        return len(self.rows)


def rows_from_columnar(
    columns: list[str],
    values: list[list[Any]],
) -> list[dict[str, Any]]:
    return [dict(zip(columns, row, strict=False)) for row in values]

"""Minimization of results before returning them to the model.

No raw dump reaches the model. Four steps, in this order:

1. Projection: keep only the requested fields, or the default projection.
2. Masking: removal of secret fields, pseudonymization of personal fields, redaction of
   sensitive patterns left in free-text values.
3. Aggregation: beyond a certain volume, return counts and a sample rather than all rows.
4. Token cap: final truncation, always signaled to the model.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from middleware.config import MaskingPolicy, Settings, TokenizationPolicy
from middleware.tokenization import TokenVault

_MAX_VALUE_CHARS = 512
_SAMPLE_ROWS = 10
_MAX_AGG_KEYS = 3

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "[jwt masked]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[aws key masked]"),
    (
        re.compile(r"(?i)\b(?:password|pwd|passwd|secret|api[_-]?key)\s*[=:]\s*\S+"),
        "[secret masked]",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}"), "[token masked]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[private key masked]",
    ),
)


@dataclass
class MinimizedResult:
    """Result ready to be sent to the model."""

    rows: list[dict[str, Any]]
    returned_rows: int
    source_rows: int
    truncated: bool = False
    aggregated: bool = False
    analyst_sample: list[dict[str, Any]] = field(default_factory=list)
    """Masked sample for the analyst (thread and report), never for the model: when the
    result is aggregated, the model receives no row."""
    aggregates: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "returned_rows": self.returned_rows,
            "source_rows": self.source_rows,
            "truncated": self.truncated,
            "rows": self.rows,
        }
        if self.aggregated:
            payload["aggregated"] = True
            payload["aggregates"] = self.aggregates
        if self.notes:
            payload["notes"] = self.notes
        return payload


def pseudonymize(value: str, policy: MaskingPolicy) -> str:
    digest = hashlib.sha256(f"{policy.hash_salt}:{value.lower()}".encode()).hexdigest()
    return f"pseudo:{digest[:12]}"


def redact_free_text(value: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned = redact_free_text(value)
        if len(cleaned) > _MAX_VALUE_CHARS:
            return cleaned[:_MAX_VALUE_CHARS] + f"… [truncated, {len(cleaned)} characters]"
        return cleaned
    if isinstance(value, (dict, list)):
        serialized = json.dumps(value, ensure_ascii=False, default=str)
        return _normalize_value(serialized)
    return value


def mask_row(
    row: dict[str, Any],
    policy: MaskingPolicy,
    *,
    tokenization: TokenizationPolicy | None = None,
    vault: TokenVault | None = None,
) -> dict[str, Any]:
    """Two passes: first record every value of the sensitively named fields in the vault,
    then produce the row. This way a value seen in a specific field is replaced
    everywhere, including in a bulk "additional" field, whatever the column order."""

    tokenize = vault is not None and tokenization is not None and tokenization.enabled

    if tokenize and tokenization is not None and vault is not None:
        for key, value in row.items():
            lowered = key.lower()
            if not isinstance(value, str) or lowered in policy.drop_fields:
                continue
            if lowered in tokenization.host_fields:
                vault.token_for("host", value)
            elif lowered in tokenization.user_fields:
                vault.token_for("user", value)
            elif lowered in policy.hash_fields:
                vault.register_substitution(value, pseudonymize(value, policy))

    masked: dict[str, Any] = {}
    for key, value in row.items():
        lowered = key.lower()
        if lowered in policy.drop_fields:
            continue
        if value is None or value == "":
            continue
        if tokenize and isinstance(value, str) and tokenization is not None and vault is not None:
            if lowered in tokenization.host_fields:
                masked[key] = vault.token_for("host", value)
                continue
            if lowered in tokenization.user_fields:
                masked[key] = vault.token_for("user", value)
                continue
        if lowered in policy.hash_fields and isinstance(value, str):
            masked[key] = pseudonymize(value, policy)
            continue
        normalized = _normalize_value(value)
        if tokenize and isinstance(normalized, str) and vault is not None:
            normalized = vault.tokenize_text(normalized)
        masked[key] = normalized
    return masked


def _project(rows: list[dict[str, Any]], fields: tuple[str, ...] | None) -> list[dict[str, Any]]:
    if not fields:
        return rows
    wanted = {name.lower() for name in fields}
    return [{key: value for key, value in row.items() if key.lower() in wanted} for row in rows]


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Count the values of low-cardinality fields, those that carry a signal."""

    if not rows:
        return {}
    total = len(rows)
    candidates: list[tuple[int, str, Counter[str]]] = []
    for key in rows[0]:
        values = [str(row.get(key)) for row in rows if row.get(key) is not None]
        if len(values) < total // 2:
            continue
        counter = Counter(values)
        cardinality = len(counter)
        if 1 < cardinality <= max(2, total // 5):
            candidates.append((cardinality, key, counter))

    candidates.sort(key=lambda item: item[0])
    return {
        key: [{"value": value, "count": count} for value, count in counter.most_common(10)]
        for _, key, counter in candidates[:_MAX_AGG_KEYS]
    }


def _estimate_tokens(rows: list[dict[str, Any]]) -> int:
    return len(json.dumps(rows, ensure_ascii=False, default=str)) // 4


def minimize(
    rows: list[dict[str, Any]],
    *,
    settings: Settings,
    fields: tuple[str, ...] | None = None,
    upstream_truncated: bool = False,
    vault: TokenVault | None = None,
) -> MinimizedResult:
    source_rows = len(rows)
    projected = _project(rows, fields)
    masked = [
        mask_row(row, settings.masking, tokenization=settings.tokenization, vault=vault)
        for row in projected
    ]

    result = MinimizedResult(
        rows=masked,
        returned_rows=len(masked),
        source_rows=source_rows,
        truncated=upstream_truncated,
        analyst_sample=[dict(row) for row in masked[:_SAMPLE_ROWS]],
    )
    if upstream_truncated:
        result.aggregates = _aggregate(masked)
        result.aggregated = True
        result.rows = []
        result.returned_rows = 0
        result.notes.append(
            f"Cap of {source_rows} rows reached: there are probably more, and such a "
            "volume cannot be analyzed row by row. No row sent - only the counts per "
            "significant field. Refine your query (stricter filters, specific entity, "
            "reduced window) to get below the cap and analyze everything row by row, or "
            "have the SIEM do the aggregation (summarize count() per entity), exhaustive "
            "by construction."
        )

    while result.rows and _estimate_tokens(result.rows) > settings.max_result_tokens:
        result.rows.pop()
        result.truncated = True

    if result.returned_rows != len(result.rows):
        result.returned_rows = len(result.rows)
        result.notes.append(
            "Sample reduced to fit within the token cap: request fewer fields (`fields`) "
            "or tighten the query for a complete view."
        )

    return result

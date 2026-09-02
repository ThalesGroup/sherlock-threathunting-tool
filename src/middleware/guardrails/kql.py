"""Static analysis of KQL queries before sending to Sentinel or Defender.

Three responsibilities, in this order:

1. Reject anything that is not a read (control commands, ingestion).
2. Reject anything that leaves the authorized scope: plugins that emit network traffic
   (`http_request`, `sql_request`, `externaldata`) and functions that change scope
   (`cluster()`, `database()`, `workspace()`), which would bypass the least privilege
   granted to the technical identity.
3. Enforce the row cap by rewriting the query.

Rejection is the default position: an unrecognized construct passes only if it contains
no forbidden pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from middleware.errors import ErrorCode, ToolError

_CONTROL_COMMAND_PREFIX = "."

_FORBIDDEN_TOKENS: dict[str, str] = {
    "externaldata": "reading data outside the workspace",
    "http_request": "outbound network call",
    "http_request_post": "outbound network call",
    "sql_request": "outbound network call",
    "mysql_request": "outbound network call",
    "postgresql_request": "outbound network call",
    "cosmosdb_sql_request": "outbound network call",
    "azure_digital_twins_query_request": "outbound network call",
    "infrastructure_insights": "out-of-scope access",
    "into": "write operation",
    "ingest": "write operation",
}

_FORBIDDEN_SCOPE_FUNCTIONS: dict[str, str] = {
    "cluster": "cluster switch",
    "database": "database switch",
    "workspace": "access to another workspace",
    "app": "access to another application",
    "adx": "access to an external cluster",
    "arg": "access to Azure Resource Graph",
}

_ALLOWED_EVALUATE_PLUGINS = frozenset(
    {
        "bag_unpack",
        "basket",
        "autocluster",
        "diffpatterns",
        "narrow",
        "pivot",
        "rolling_percentile",
        "sequence_detect",
        "dcount_intersect",
        "preview",
        "schema_merge",
    }
)

_TIMESPAN_UNITS_IN_DAYS: dict[str, float] = {
    "d": 1.0,
    "h": 1 / 24,
    "m": 1 / 1440,
    "s": 1 / 86400,
    "ms": 1 / 86_400_000,
    "microsecond": 1 / 86_400_000_000,
    "tick": 1 / 864_000_000_000,
}

_AGO_RE = re.compile(r"\bago\s*\(\s*(\d+(?:\.\d+)?)\s*(microsecond|tick|ms|d|h|m|s)\s*\)", re.I)
_EVALUATE_RE = re.compile(r"\bevaluate\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
_IDENT_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class KqlPlan:
    """Accepted query, rewritten with the row cap."""

    query: str
    row_cap: int
    notes: tuple[str, ...] = field(default=())


def _strip_comments(query: str) -> str:
    """Remove `//` comments without breaking strings that contain `//`."""

    out: list[str] = []
    i = 0
    length = len(query)
    quote: str | None = None
    while i < length:
        char = query[i]
        if quote is not None:
            out.append(char)
            if char == "\\" and i + 1 < length:
                out.append(query[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            i += 1
            continue
        if char == "/" and i + 1 < length and query[i + 1] == "/":
            while i < length and query[i] != "\n":
                i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _mask_string_literals(query: str) -> str:
    """Replace string contents with blanks for lexical analysis.

    An IOC value or a file path may contain a forbidden word; only the structure of the
    query must be analyzed, never the literals.
    """

    out: list[str] = []
    i = 0
    length = len(query)
    quote: str | None = None
    while i < length:
        char = query[i]
        if quote is not None:
            if char == "\\" and i + 1 < length:
                out.append("  ")
                i += 2
                continue
            if char == quote:
                quote = None
                out.append(char)
            else:
                out.append(" ")
            i += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            i += 1
            continue
        out.append(char)
        i += 1
    if quote is not None:
        raise ToolError(
            ErrorCode.QUERY_REJECTED,
            "Unterminated string in the query.",
            hint="Check the quotes.",
        )
    return "".join(out)


def _split_top_level(text: str, separator: str) -> list[str]:
    """Split on a separator, ignoring parentheses, brackets and quotes."""

    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if quote is not None:
            current.append(char)
            if char == "\\" and i + 1 < len(text):
                current.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "\"'":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def _reject(reason: str, hint: str | None = None) -> ToolError:
    return ToolError(ErrorCode.QUERY_REJECTED, f"Query rejected: {reason}.", hint=hint)


def _check_forbidden_constructs(skeleton: str) -> None:
    lowered = skeleton.lower()

    for word in _WORD_RE.findall(lowered):
        if word in _FORBIDDEN_TOKENS:
            raise _reject(
                f"the operator `{word}` is forbidden ({_FORBIDDEN_TOKENS[word]})",
                hint="Only reading data from the authorized scope is permitted.",
            )

    for match in _IDENT_CALL_RE.finditer(lowered):
        name = match.group(1)
        if name in _FORBIDDEN_SCOPE_FUNCTIONS:
            raise _reject(
                f"the function `{name}()` is forbidden ({_FORBIDDEN_SCOPE_FUNCTIONS[name]})",
                hint="Query only the source designated by the tool.",
            )

    for match in _EVALUATE_RE.finditer(lowered):
        plugin = match.group(1)
        if plugin not in _ALLOWED_EVALUATE_PLUGINS:
            raise _reject(
                f"the plugin `evaluate {plugin}` is not in the allowlist",
                hint="Allowed plugins: " + ", ".join(sorted(_ALLOWED_EVALUATE_PLUGINS)),
            )


def _check_statements(skeleton: str) -> None:
    statements = [part.strip() for part in _split_top_level(skeleton, ";")]
    statements = [part for part in statements if part]
    if not statements:
        raise _reject("empty query")

    for statement in statements:
        if statement.startswith(_CONTROL_COMMAND_PREFIX):
            raise _reject(
                "control commands (prefixed with a dot) are forbidden",
                hint="Only tabular read queries are accepted.",
            )
        head = statement.split(None, 1)[0].lower() if statement.split() else ""
        if head == "set":
            raise _reject(
                "the `set` directive is forbidden",
                hint="Query options are set by the platform.",
            )

    body = statements[-1]
    if body.lower().startswith("let "):
        raise _reject(
            "the query ends with a `let` declaration and produces no result",
            hint="End with a tabular expression.",
        )


def _apply_row_cap(query: str, row_cap: int) -> str:
    """Add a safety `| take N` at the end of the query.

    Applied after all other operators, the cap bounds the result whatever the query asks
    for upstream. If the query ends with `render`, the `take` is inserted just before it,
    since `render` must remain the last operator.
    """

    statements = _split_top_level(query, ";")
    while len(statements) > 1 and not statements[-1].strip():
        statements.pop()
    body = statements[-1].rstrip()
    segments = _split_top_level(body, "|")
    last = segments[-1].strip().lower()

    if last.startswith("render"):
        segments.insert(len(segments) - 1, f" take {row_cap} ")
    else:
        segments.append(f" take {row_cap}")

    statements[-1] = "|".join(segments)
    return ";".join(statements)


def _max_ago_days(skeleton: str) -> float | None:
    values = [
        float(amount) * _TIMESPAN_UNITS_IN_DAYS[unit.lower()]
        for amount, unit in _AGO_RE.findall(skeleton)
    ]
    return max(values) if values else None


def validate_kql(
    query: str,
    *,
    row_cap: int,
    require_time_filter_days: int | None = None,
) -> KqlPlan:
    """Validate a KQL query and return its capped version.

    `require_time_filter_days` is used for Defender, whose API accepts no window
    parameter: the time bound must then be carried by the query itself, so it is checked
    here. For Sentinel, the window is passed to the API and checked service-side, so this
    parameter stays None.
    """

    if not query or not query.strip():
        raise _reject("empty query")

    cleaned = _strip_comments(query).strip()
    if not cleaned:
        raise _reject("empty query after removing comments")

    skeleton = _mask_string_literals(cleaned)

    _check_statements(skeleton)
    _check_forbidden_constructs(skeleton)

    notes: list[str] = []

    if require_time_filter_days is not None:
        window = _max_ago_days(skeleton)
        if window is None:
            raise ToolError(
                ErrorCode.WINDOW_TOO_LARGE,
                "The query carries no time filter.",
                hint=(
                    "This source accepts no window parameter: add a filter "
                    f"`where Timestamp > ago(Nd)` with N less than or equal to "
                    f"{require_time_filter_days}."
                ),
            )
        if window > require_time_filter_days:
            raise ToolError(
                ErrorCode.WINDOW_TOO_LARGE,
                f"Requested window of {window:g} days, cap {require_time_filter_days} days.",
                hint="Reduce the period or query Sentinel if the table is ingested there.",
            )
        notes.append(f"window checked: {window:g} days")

    capped = _apply_row_cap(cleaned, row_cap)
    notes.append(f"cap of {row_cap} rows applied by the platform")

    return KqlPlan(query=capped, row_cap=row_cap, notes=tuple(notes))

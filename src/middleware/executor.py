"""Single funnel for executing SIEM queries.

No tool calls a SIEM directly. Every execution follows the same order, and the order
matters: the controls that protect the scope run before those that cost a network call,
and nothing is executed before the human checkpoint has been cleared.

    IOC checkpoint -> caps -> query analysis -> sourced indicators
    -> budget -> quota -> execution -> minimization -> journal -> encapsulation

What leaves here is already minimized and already encapsulated: the model never sees
anything else.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from middleware.anonymizer import FAILSAFE_MASK, SemanticAnonymizer
from middleware.audit import AuditEventType, AuditJournal
from middleware.budgets import HuntBudget
from middleware.clients.defender import DefenderClient
from middleware.clients.results import QueryOutcome
from middleware.clients.secops import SecOpsClient
from middleware.clients.sentinel import SentinelClient
from middleware.config import Settings
from middleware.errors import ErrorCode, ToolError
from middleware.guardrails.ioc import (
    Ioc,
    assert_checkpoint_passed,
    assert_query_indicators_validated,
)
from middleware.guardrails.kql import validate_kql
from middleware.guardrails.udm import validate_udm, validate_window
from middleware.minimization import minimize
from middleware.ratelimit import RateLimiter, build_limiters
from middleware.tokenization import TokenVault, find_tokens
from middleware.untrusted import wrap_rows


@dataclass(frozen=True)
class QueryRecord:
    """Trace of a query actually executed. Serves as evidence attachable to a finding."""

    query_id: str
    siem: str
    query: str
    executed_at: str
    returned_rows: int
    source_rows: int
    truncated: bool
    duration_ms: int
    intent: str | None = None
    columns: tuple[str, ...] = ()
    sample: tuple[dict[str, Any], ...] = ()
    model_sample: tuple[dict[str, Any], ...] = ()
    """The same rows as transmitted to the model: pseudonyms in place, free text masked
    where applicable. This is the visible proof of anonymization."""
    anonymization: dict[str, Any] = field(default_factory=dict)
    interpretation: str | None = None
    """What the agent said about the result right after receiving it — its actual reading,
    never regenerated after the fact. Attached by the orchestrator on the following turn."""


def record_to_payload(record: QueryRecord) -> dict[str, Any]:
    return {
        "query_id": record.query_id,
        "siem": record.siem,
        "query": record.query,
        "executed_at": record.executed_at,
        "returned_rows": record.returned_rows,
        "source_rows": record.source_rows,
        "truncated": record.truncated,
        "duration_ms": record.duration_ms,
        "intent": record.intent,
        "columns": list(record.columns),
        "sample": [dict(row) for row in record.sample],
        "model_sample": [dict(row) for row in record.model_sample],
        "anonymization": dict(record.anonymization),
        "interpretation": record.interpretation,
    }


def record_from_payload(payload: dict[str, Any]) -> QueryRecord:
    return QueryRecord(
        query_id=str(payload["query_id"]),
        siem=str(payload["siem"]),
        query=str(payload["query"]),
        executed_at=str(payload["executed_at"]),
        returned_rows=int(payload["returned_rows"]),
        source_rows=int(payload["source_rows"]),
        truncated=bool(payload["truncated"]),
        duration_ms=int(payload["duration_ms"]),
        intent=payload.get("intent"),
        columns=tuple(payload.get("columns") or ()),
        sample=tuple(dict(row) for row in payload.get("sample") or ()),
        model_sample=tuple(dict(row) for row in payload.get("model_sample") or ()),
        anonymization=dict(payload.get("anonymization") or {}),
        interpretation=payload.get("interpretation"),
    )


_ANALYST_SAMPLE_ROWS = 10


@dataclass
class QueryLedger:
    """Registry of the hunt's queries. A finding can only cite what it contains."""

    records: dict[str, QueryRecord] = field(default_factory=dict)

    def add(self, record: QueryRecord) -> None:
        self.records[record.query_id] = record

    def unknown_ids(self, query_ids: list[str]) -> list[str]:
        return [query_id for query_id in query_ids if query_id not in self.records]

    def as_list(self) -> list[QueryRecord]:
        return list(self.records.values())


def summarize_anonymization(
    rows: list[dict[str, Any]], *, semantic: str, tokenization: bool
) -> dict[str, Any]:
    """What the model received, in numbers: distinct pseudonyms per family, fields masked
    by the fail-closed safeguard, state of the semantic pass."""

    distinct: dict[str, set[str]] = {"HOST": set(), "USER": set(), "IP-INT": set(), "DATA": set()}
    masked = 0
    for row in rows:
        for value in row.values():
            if not isinstance(value, str):
                continue
            if value == FAILSAFE_MASK:
                masked += 1
            for token in find_tokens(value):
                distinct[token.rsplit("-", 1)[0]].add(token)
    return {
        "semantic": semantic,
        "tokenization": tokenization,
        "masked_fields": masked,
        "tokens": {family: len(values) for family, values in distinct.items()},
    }


def _columns(rows: list[dict[str, Any]]) -> tuple[str, ...]:
    ordered: dict[str, None] = {}
    for row in rows:
        for key in row:
            ordered.setdefault(key, None)
    return tuple(ordered)


def _anonymization_degraded_note(*, masked: bool) -> str:
    if masked:
        return (
            "semantic anonymization unavailable: the free-text fields of this result have "
            "been masked as a precaution. This masking is not an absence of data: do not "
            "conclude on these fields, work on the atomic fields (file names, hashes, URLs, "
            "ports) or by aggregation."
        )
    return (
        "semantic anonymization unavailable: only the deterministic layer was applied to "
        "this result."
    )


class SiemExecutor:
    def __init__(
        self,
        *,
        settings: Settings,
        journal: AuditJournal,
        budget: HuntBudget,
        ledger: QueryLedger,
        sentinel: SentinelClient | None = None,
        defender: DefenderClient | None = None,
        secops: SecOpsClient | None = None,
        limiters: dict[str, RateLimiter] | None = None,
        vault: TokenVault | None = None,
        anonymizer: SemanticAnonymizer | None = None,
        window: tuple[datetime, datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._journal = journal
        self._budget = budget
        self._ledger = ledger
        self._sentinel = sentinel
        self._defender = defender
        self._secops = secops
        self._window = window
        """Investigation period set by the analyst when creating the hunt. The windows
        requested by the model are bounded to it on the middleware side: outside the
        period, a query is reduced to the intersection or refused."""
        self._iocs: list[Ioc] = []
        self._limiters = limiters or _default_limiters(settings)
        self._vault = vault if settings.tokenization.enabled else None
        self._anonymizer = anonymizer if self._vault is not None else None

    def _to_internal(self, query: str) -> str:
        """The model pivots on pseudonyms; the SIEM receives the real values."""

        return self._vault.detokenize_text(query) if self._vault else query

    def _to_model(self, text: str) -> str:
        return self._vault.tokenize_text(text) if self._vault else text

    def set_iocs(self, iocs: list[Ioc]) -> None:
        """Receives all of the hunt's indicators, not only the validated ones.

        The human checkpoint needs to see those still pending: it is their presence that
        blocks access to the SIEMs. Passing only the validated ones would amount to removing
        the control.
        """

        self._iocs = iocs

    @property
    def iocs(self) -> list[Ioc]:
        return self._iocs

    async def run_sentinel(
        self,
        *,
        kql_query: str,
        workspace: str,
        timespan_days: int | None = None,
        max_rows: int | None = None,
        fields: tuple[str, ...] | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        kql_query = self._to_internal(kql_query)
        caps = self._settings.sentinel
        window = min(timespan_days or caps.window_days_default, caps.window_days_max)
        row_cap = caps.clamp_rows(max_rows)

        plan = await self._prepare(
            siem="sentinel",
            query=kql_query,
            validate=lambda: validate_kql(kql_query, row_cap=row_cap),
        )

        workspace_id = self._resolve_workspace(workspace)
        client = self._require(self._sentinel, "sentinel")
        timespan_override: str | None = None
        window_note = f"applied window: {window} days"
        if self._window is not None:
            window_start, window_end = self._window
            timespan_override = f"{window_start.isoformat()}/{window_end.isoformat()}"
            window_note = (
                "investigation period set by the analyst: "
                f"{window_start.isoformat()} -> {window_end.isoformat()}"
            )
        timespan_extra = {"timespan": timespan_override} if timespan_override else {}
        outcome = await self._call(
            "sentinel",
            lambda: client.run_query(
                query=plan.query,
                workspace_id=workspace_id,
                timespan_days=window,
                row_cap=row_cap,
                **timespan_extra,
            ),
            query=plan.query,
        )
        return await self._deliver(
            siem="sentinel",
            executed_query=plan.query,
            outcome=outcome,
            fields=fields,
            notes=[*plan.notes, window_note],
            intent=intent,
        )

    async def run_defender(
        self,
        *,
        kql_query: str,
        timespan_days: int | None = None,
        max_rows: int | None = None,
        fields: tuple[str, ...] | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        kql_query = self._to_internal(kql_query)
        caps = self._settings.defender
        window = min(timespan_days or caps.window_days_max, caps.window_days_max)
        row_cap = caps.clamp_rows(max_rows)

        defender_window_notes: list[str] = []
        if self._window is not None:
            window_start, window_end = self._window
            days_back = (datetime.now(UTC) - window_start).total_seconds() / 86_400
            window = max(1, min(window, int(days_back) + 1))
            defender_window_notes.append(
                "investigation period enforced: depth bounded to "
                f"{window_start.isoformat()}. The Defender API cannot exclude events "
                f"later than {window_end.isoformat()}: filter on Timestamp in the query "
                "if necessary."
            )

        plan = await self._prepare(
            siem="defender",
            query=kql_query,
            validate=lambda: validate_kql(
                kql_query, row_cap=row_cap, require_time_filter_days=window
            ),
        )

        client = self._require(self._defender, "defender")
        outcome = await self._call(
            "defender",
            lambda: client.run_query(query=plan.query, row_cap=row_cap),
            query=plan.query,
        )
        return await self._deliver(
            siem="defender",
            executed_query=plan.query,
            outcome=outcome,
            fields=fields,
            notes=[*plan.notes, *defender_window_notes],
            intent=intent,
        )

    async def run_secops(
        self,
        *,
        udm_query: str,
        start_time: str,
        end_time: str,
        max_rows: int | None = None,
        fields: tuple[str, ...] | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        udm_query = self._to_internal(udm_query)
        caps = self._settings.secops
        row_cap = caps.clamp_rows(max_rows)
        try:
            start, end = validate_window(start_time, end_time, max_days=caps.window_days_max)
        except ToolError as error:
            await self._journal.record(
                AuditEventType.QUERY_REJECTED,
                siem="secops",
                query=udm_query,
                error_code=error.code.value,
                detail={
                    "message": error.message,
                    "stage": "time window",
                    "start_time": start_time,
                    "end_time": end_time,
                },
            )
            raise

        plan = await self._prepare(
            siem="secops",
            query=udm_query,
            validate=lambda: validate_udm(udm_query, row_cap=row_cap),
        )

        start, end, window_notes = await self._clamp_to_window(
            siem="secops", query=udm_query, start_iso=start, end_iso=end
        )

        client = self._require(self._secops, "secops")
        outcome = await self._call(
            "secops",
            lambda: client.run_query(
                query=plan.query, start_time=start, end_time=end, row_cap=row_cap
            ),
            query=plan.query,
        )
        return await self._deliver(
            siem="secops",
            executed_query=plan.query,
            outcome=outcome,
            fields=fields,
            notes=[*plan.notes, f"window: {start} -> {end}", *window_notes],
            intent=intent,
        )

    async def _clamp_to_window(
        self, *, siem: str, query: str, start_iso: str, end_iso: str
    ) -> tuple[str, str, list[str]]:
        """Bounds an absolute window to the enforced investigation period."""

        if self._window is None:
            return start_iso, end_iso, []
        window_start, window_end = self._window
        start = max(datetime.fromisoformat(start_iso), window_start)
        end = min(datetime.fromisoformat(end_iso), window_end)
        if end <= start:
            error = ToolError(
                ErrorCode.QUERY_REJECTED,
                "Requested window entirely outside the investigation period.",
                hint=(
                    f"Period set by the analyst: {window_start.isoformat()} -> "
                    f"{window_end.isoformat()}. Query within it."
                ),
            )
            await self._journal.record(
                AuditEventType.QUERY_REJECTED,
                siem=siem,
                query=query,
                error_code=error.code.value,
                detail={"message": error.message, "stage": "investigation period"},
            )
            raise error
        notes = []
        if start.isoformat() != start_iso or end.isoformat() != end_iso:
            notes.append(
                "window bounded to the investigation period set by the analyst "
                f"({window_start.isoformat()} -> {window_end.isoformat()})"
            )
        return start.isoformat(), end.isoformat(), notes

    async def _prepare(self, *, siem: str, query: str, validate: Any) -> Any:
        self._budget.check_alive()
        try:
            assert_checkpoint_passed(self._iocs, hunt_id=self._journal.hunt_id)
            plan = validate()
            assert_query_indicators_validated(plan.query, self._iocs)
        except ToolError as error:
            await self._journal.record(
                AuditEventType.QUERY_REJECTED,
                siem=siem,
                query=query,
                error_code=error.code.value,
                detail={"message": error.message},
            )
            raise
        self._budget.consume_siem_query()
        return plan

    async def _call(self, siem: str, call: Any, *, query: str) -> QueryOutcome:
        limiter = self._limiters.get(siem)
        if limiter:
            await limiter.acquire()
        try:
            return await call()
        except ToolError as error:
            await self._journal.record(
                AuditEventType.QUERY_REJECTED,
                siem=siem,
                query=query,
                error_code=error.code.value,
                detail={"message": error.message, "hint": error.hint, "stage": "upstream call"},
            )
            raise

    async def _deliver(
        self,
        *,
        siem: str,
        executed_query: str,
        outcome: QueryOutcome,
        fields: tuple[str, ...] | None,
        notes: list[str],
        intent: str | None = None,
    ) -> dict[str, Any]:
        minimized = minimize(
            outcome.rows,
            settings=self._settings,
            fields=fields,
            upstream_truncated=outcome.truncated,
            vault=self._vault,
        )
        query_id = f"q_{uuid.uuid4().hex[:10]}"
        semantic = "disabled"
        if self._anonymizer is not None:
            aggregate_rows = [
                item
                for values in minimized.aggregates.values()
                for item in values
                if isinstance(item, dict)
            ]
            scrub = await self._anonymizer.scrub([*minimized.rows, *aggregate_rows])
            minimized.rows = scrub.rows[: len(minimized.rows)]
            scrubbed_aggregates = scrub.rows[len(minimized.rows) :]
            index = 0
            for values in minimized.aggregates.values():
                for position in range(len(values)):
                    if isinstance(values[position], dict):
                        values[position] = scrubbed_aggregates[index]
                        index += 1
            semantic = "degraded" if scrub.degraded else "active"
            if scrub.degraded:
                notes = [*notes, _anonymization_degraded_note(masked=scrub.masked)]
                await self._journal.record(
                    AuditEventType.ANONYMIZATION_DEGRADED,
                    siem=siem,
                    query_id=query_id,
                    detail={
                        "reason": scrub.degraded,
                        "free_text_masked": scrub.masked,
                        "rows": len(minimized.rows),
                    },
                )
        record = QueryRecord(
            query_id=query_id,
            siem=siem,
            query=executed_query,
            executed_at=datetime.now(UTC).isoformat(),
            returned_rows=minimized.returned_rows,
            source_rows=minimized.source_rows,
            truncated=minimized.truncated,
            duration_ms=outcome.duration_ms,
            intent=self._to_internal(intent) if intent else None,
            columns=_columns(minimized.rows),
            sample=tuple(
                self._to_internal_row(row)
                for row in minimized.analyst_sample[:_ANALYST_SAMPLE_ROWS]
            ),
            model_sample=tuple(dict(row) for row in minimized.rows[:_ANALYST_SAMPLE_ROWS]),
            anonymization=summarize_anonymization(
                [
                    *minimized.rows,
                    *(
                        {"aggregate": item}
                        for values in minimized.aggregates.values()
                        for item in values
                    ),
                ],
                semantic=semantic,
                tokenization=self._vault is not None,
            ),
        )
        self._ledger.add(record)

        await self._journal.record(
            AuditEventType.QUERY_EXECUTED,
            siem=siem,
            query_id=query_id,
            query=executed_query,
            rows_returned=minimized.source_rows,
            truncated=minimized.truncated,
            duration_ms=outcome.duration_ms,
        )

        payload = minimized.to_payload()
        rows = payload.pop("rows")
        payload["notes"] = [*notes, *payload.get("notes", [])]
        payload["query_id"] = query_id
        payload["siem"] = siem
        payload["executed_query"] = self._to_model(executed_query)
        payload["data"] = wrap_rows(rows, source=siem, reference=query_id)
        return payload

    def _to_internal_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Sample destined for the analyst: reversible pseudonyms are rehydrated, values
        masked irreversibly (secrets, free text) stay masked."""

        return {
            key: self._to_internal(value) if isinstance(value, str) else value
            for key, value in row.items()
        }

    def _resolve_workspace(self, alias: str) -> str:
        """Translate the model-facing logical alias into the real identifier, never the reverse."""

        aliases = self._settings.workspace_aliases
        if alias not in aliases:
            if len(aliases) == 1:
                # A single workspace configured: the wrong alias designates nothing else,
                # so route to it rather than making the model waste an iteration.
                return next(iter(aliases.values()))
            known = ", ".join(sorted(aliases)) or "none"
            raise ToolError(
                ErrorCode.UNKNOWN_TARGET,
                f"Unknown workspace: {alias}.",
                hint=f"Available workspaces: {known}.",
            )
        return aliases[alias]

    def _require(self, client: Any, siem: str) -> Any:
        if client is None:
            raise ToolError(
                ErrorCode.UNKNOWN_TARGET,
                f"The {siem} source is not configured on this installation.",
                hint="Use another source or conclude with the material available.",
            )
        return client


def _default_limiters(settings: Settings) -> dict[str, RateLimiter]:
    limits = settings.rate_limits
    return {
        "sentinel": build_limiters(per_minute=limits.sentinel_per_minute, name="Sentinel"),
        "defender": build_limiters(
            per_minute=limits.defender_per_minute,
            per_hour=limits.defender_per_hour,
            name="Defender",
        ),
        "secops": build_limiters(per_minute=limits.secops_per_minute, name="SecOps"),
    }

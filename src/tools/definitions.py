"""Tools exposed to the model. Exhaustive, closed list.

There is no write tool on any SIEM, no response action, no tool behind a feature flag.
Absence is the mechanism: whatever is not declared here is not callable, whatever the
content of the prompt or of a log.

Threat intelligence search is not exposed to the model: it lives in a separate registry
(`build_enrichment_registry`), invocable only through the analyst path, in the upstream
phase. During the investigation loop, the agent has materially no tool whose flow leaves
the internal scope: a string read from a log cannot be turned into an outbound query.

Each tool validates its inputs against a strict schema before execution. A non-compliant
input never reaches the middleware.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from middleware.audit import AuditEventType, AuditJournal
from middleware.clients.ti import ThreatIntelConnector
from middleware.errors import BudgetExhausted, ErrorCode, ToolError
from middleware.executor import SiemExecutor
from middleware.guardrails.ioc import IocStatus, IocType, summarize_for_model
from middleware.tokenization import TokenVault
from reporting.dossier import Dossier
from reporting.models import (
    AttackTechnique,
    Confidence,
    Entity,
    Severity,
    TimelineEvent,
    Verdict,
)


class GetIocsForCampaign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_name: str = Field(min_length=2, max_length=120)
    ioc_types: list[IocType] | None = None
    max_results: int = Field(default=50, ge=1, le=200)
    time_range: Literal["month", "3months", "9months", "year"] | None = None


class RunSecopsQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str = Field(
        min_length=10,
        max_length=300,
        description=(
            "What you are looking for with this query, in one sentence: shown to the "
            "analyst following the hunt, next to the result."
        ),
    )
    udm_query: str = Field(min_length=3)
    start_time: str
    end_time: str
    max_rows: int | None = Field(default=None, ge=1, le=500)
    fields: list[str] | None = None


class RunSentinelKql(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str = Field(
        min_length=10,
        max_length=300,
        description=(
            "What you are looking for with this query, in one sentence: shown to the "
            "analyst following the hunt, next to the result."
        ),
    )
    kql_query: str = Field(min_length=3)
    workspace: str = Field(min_length=1, max_length=64)
    timespan_days: int = Field(default=7, ge=1, le=30)
    max_rows: int | None = Field(default=None, ge=1, le=500)
    fields: list[str] | None = None


class RunDefenderHunting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str = Field(
        min_length=10,
        max_length=300,
        description=(
            "What you are looking for with this query, in one sentence: shown to the "
            "analyst following the hunt, next to the result."
        ),
    )
    kql_query: str = Field(min_length=3)
    timespan_days: int | None = Field(
        default=None,
        ge=1,
        le=30,
        description=(
            "Maximum depth in days (1 to 30). Optional: by default, the depth is that of "
            "the time filter carried by the query, up to 30 days."
        ),
    )
    max_rows: int | None = Field(default=None, ge=1, le=500)
    fields: list[str] | None = None


class RecordFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10)
    severity: Severity
    confidence: Confidence
    entities: list[Entity] = Field(default_factory=list)
    evidence_query_ids: list[str] = Field(min_length=1)


class ConcludeHunt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    summary: str = Field(min_length=20)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    limitations: str = Field(min_length=10)
    attack_description: str | None = Field(
        default=None,
        min_length=40,
        max_length=2000,
        description=(
            "Presentation of the hunted attack for a non-specialist reader: modus "
            "operandi, attacker's objective, why it is hard to detect."
        ),
    )
    techniques: list[AttackTechnique] = Field(
        default_factory=list,
        max_length=8,
        description="MITRE ATT&CK techniques targeted by the hunt (id, name, summary).",
    )
    recommendation: str | None = Field(
        default=None,
        min_length=10,
        max_length=1500,
        description=(
            "Suggested next step for the analyst (manual review, monitoring, no action). "
            "A proposal, never an executed action."
        ),
    )


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema_model: type[BaseModel]
    handler: Callable[[Any], Awaitable[dict[str, Any]]]
    requires_ioc_checkpoint: bool

    def as_function_schema(self) -> dict[str, Any]:
        parameters = self.schema_model.model_json_schema()
        parameters.pop("title", None)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": parameters,
            },
        }


class ToolRegistry:
    """Single dispatch point. A name absent from the registry is not callable."""

    def __init__(self, specs: list[ToolSpec], journal: AuditJournal) -> None:
        self._specs = {spec.name: spec for spec in specs}
        self._journal = journal

    @property
    def names(self) -> list[str]:
        return sorted(self._specs)

    def function_schemas(self) -> list[dict[str, Any]]:
        return [spec.as_function_schema() for spec in self._specs.values()]

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool and always return a payload the model can act on.

        Business errors are converted into a structured response so the model can correct
        its approach. Only budget exhaustion interrupts the loop.
        """

        spec = self._specs.get(name)
        if spec is None:
            return ToolError(
                ErrorCode.SCHEMA_INVALID,
                f"Unknown tool: {name}.",
                hint="Available tools: " + ", ".join(self.names),
            ).to_payload()

        try:
            payload = spec.schema_model.model_validate(arguments)
        except ValidationError as error:
            return ToolError(
                ErrorCode.SCHEMA_INVALID,
                f"Invalid arguments for {name}: {_first_error(error)}.",
            ).to_payload()

        try:
            return await spec.handler(payload)
        except BudgetExhausted:
            raise
        except ToolError as error:
            return error.to_payload()


def _first_error(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "body"
    return f"{location}: {first.get('msg', 'invalid value')}"


def build_registry(
    *,
    executor: SiemExecutor,
    dossier: Dossier,
    journal: AuditJournal,
    vault: TokenVault | None = None,
    workspaces: tuple[str, ...] = (),
) -> ToolRegistry:
    def _internal(text: str) -> str:
        """The model writes with pseudonyms; the dossier stores the real values."""

        return vault.detokenize_text(text) if vault else text

    async def run_secops(payload: RunSecopsQuery) -> dict[str, Any]:
        return await executor.run_secops(
            udm_query=payload.udm_query,
            start_time=payload.start_time,
            end_time=payload.end_time,
            max_rows=payload.max_rows,
            fields=tuple(payload.fields) if payload.fields else None,
            intent=payload.intent,
        )

    async def run_sentinel(payload: RunSentinelKql) -> dict[str, Any]:
        return await executor.run_sentinel(
            kql_query=payload.kql_query,
            workspace=payload.workspace,
            timespan_days=payload.timespan_days,
            max_rows=payload.max_rows,
            fields=tuple(payload.fields) if payload.fields else None,
            intent=payload.intent,
        )

    async def run_defender(payload: RunDefenderHunting) -> dict[str, Any]:
        return await executor.run_defender(
            kql_query=payload.kql_query,
            timespan_days=payload.timespan_days,
            max_rows=payload.max_rows,
            fields=tuple(payload.fields) if payload.fields else None,
            intent=payload.intent,
        )

    async def record_finding(payload: RecordFinding) -> dict[str, Any]:
        finding = dossier.add_finding(
            title=_internal(payload.title),
            description=_internal(payload.description),
            severity=payload.severity,
            confidence=payload.confidence,
            evidence_query_ids=payload.evidence_query_ids,
            entities=[
                entity.model_copy(update={"value": _internal(entity.value)})
                for entity in payload.entities
            ],
        )
        await journal.record(
            AuditEventType.FINDING_RECORDED,
            detail={
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "evidence": finding.evidence_query_ids,
            },
        )
        return {"finding_id": finding.id, "recorded": True}

    async def conclude(payload: ConcludeHunt) -> dict[str, Any]:
        dossier.conclude(
            verdict=payload.verdict,
            summary=_internal(payload.summary),
            limitations=_internal(payload.limitations),
            timeline=[
                event.model_copy(
                    update={"event": _internal(event.event), "source": _internal(event.source)}
                )
                for event in payload.timeline
            ],
            attack_description=(
                _internal(payload.attack_description) if payload.attack_description else None
            ),
            techniques=[
                technique.model_copy(update={"description": _internal(technique.description)})
                for technique in payload.techniques
            ],
            recommendation=_internal(payload.recommendation) if payload.recommendation else None,
        )
        await journal.record(
            AuditEventType.HUNT_CONCLUDED,
            detail={"proposed_verdict": payload.verdict.value, "findings": len(dossier.findings)},
        )
        return {
            "concluded": True,
            "proposed_verdict": payload.verdict.value,
            "note": "The verdict is a proposal: it goes to analyst review.",
        }

    specs = [
        ToolSpec(
            name="run_secops_query",
            description=(
                "Run a read-only UDM search on Google SecOps. The time window is bounded "
                "by the tenant's retention."
            ),
            schema_model=RunSecopsQuery,
            handler=run_secops,
            requires_ioc_checkpoint=True,
        ),
        ToolSpec(
            name="run_sentinel_kql",
            description=(
                "Run a read-only KQL query on a Sentinel workspace designated by its "
                "logical alias. A row cap is added by the platform."
                + (
                    " Valid workspace aliases: " + ", ".join(workspaces) + "."
                    if workspaces
                    else ""
                )
            ),
            schema_model=RunSentinelKql,
            handler=run_sentinel,
            requires_ioc_checkpoint=True,
        ),
        ToolSpec(
            name="run_defender_hunting",
            description=(
                "Run an Advanced Hunting query on Microsoft Defender. The API only returns "
                "the last 30 days: the query must carry its own time filter, for example "
                "`where Timestamp > ago(30d)`, bounded by the investigation period."
            ),
            schema_model=RunDefenderHunting,
            handler=run_defender,
            requires_ioc_checkpoint=True,
        ),
        ToolSpec(
            name="record_finding",
            description=(
                "Record a finding in the investigation dossier. Internal write only, no "
                "effect on the SIEMs. Each finding must cite the ids of the queries that "
                "support it."
            ),
            schema_model=RecordFinding,
            handler=record_finding,
            requires_ioc_checkpoint=False,
        ),
        ToolSpec(
            name="conclude_hunt",
            description=(
                "Close the investigation and trigger report generation. The `limitations` "
                "field is mandatory: it states what the hunt could not cover. Also fill in "
                "`attack_description` and `techniques` (presentation of the hunted attack, "
                "at the top of the report) and `recommendation` (suggested next step)."
            ),
            schema_model=ConcludeHunt,
            handler=conclude,
            requires_ioc_checkpoint=False,
        ),
    ]

    return ToolRegistry(specs, journal)


def build_enrichment_registry(
    *,
    dossier: Dossier,
    journal: AuditJournal,
    threat_intel: ThreatIntelConnector | None = None,
) -> ToolRegistry:
    """Registry for the enrichment phase, never exposed to the model.

    Its only tool is threat intelligence search, the sole outbound flow from the scope.
    It is invocable only through the analyst path (`/enrich`), upstream of the indicator
    validation checkpoint: during the investigation loop, this registry does not exist for
    the agent, which materially cuts any channel between a SIEM result and an outbound
    query.
    """

    async def get_iocs(payload: GetIocsForCampaign) -> dict[str, Any]:
        if threat_intel is None or not threat_intel.enabled:
            raise ToolError(
                ErrorCode.EGRESS_BLOCKED,
                "No threat intelligence source is enabled on this installation.",
                hint="Continue with the indicators provided by the analyst.",
            )
        found, dropped = await threat_intel.search(
            payload.campaign_name,
            ioc_types=tuple(payload.ioc_types) if payload.ioc_types else None,
            max_results=payload.max_results,
            time_range=payload.time_range,
        )
        by_key = {ioc.normalized(): index for index, ioc in enumerate(dossier.iocs)}
        added = 0
        refreshed = 0
        for ioc in found:
            key = ioc.normalized()
            index = by_key.get(key)
            if index is None:
                dossier.iocs.append(ioc)
                by_key[key] = len(dossier.iocs) - 1
                added += 1
                continue
            existing = dossier.iocs[index]
            # A new search refreshes what is still pending (source, corroborations,
            # dates) but never touches what the analyst has decided: a validated or
            # rejected indicator stays as is, an indicator provided by the analyst stays
            # theirs.
            if existing.status is IocStatus.PENDING_VALIDATION and not (
                existing.source_url.startswith("internal://")
            ):
                dossier.iocs[index] = ioc
                refreshed += 1

        await journal.record(
            AuditEventType.IOC_SEARCH,
            detail={
                "campaign": payload.campaign_name,
                "found": len(found),
                "added": added,
                "refreshed": refreshed,
                "dropped_unsourced": len(dropped),
            },
        )
        return {
            "iocs": summarize_for_model(found),
            "dropped_without_source": len(dropped),
            "status": "pending_validation",
            "note": (
                "These indicators cannot feed any SIEM query before validation by the "
                "analyst."
            ),
        }

    specs = [
        ToolSpec(
            name="get_iocs_for_campaign",
            description=(
                "Search for indicators associated with a campaign, actor or TTP on the "
                "approved threat intelligence sources. Only the campaign name leaves the "
                "internal scope. The returned indicators are pending analyst validation and "
                "cannot feed any SIEM query before it."
            ),
            schema_model=GetIocsForCampaign,
            handler=get_iocs,
            requires_ioc_checkpoint=False,
        ),
    ]

    return ToolRegistry(specs, journal)

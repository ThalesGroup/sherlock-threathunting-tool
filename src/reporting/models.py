"""Investigation dossier models: findings, timeline, report.

Structuring rule: a finding that cannot be tied to a query actually executed does not
exist. It is enforced by the type (`evidence_query_ids` required and non-empty) then
checked against the hunt's query ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    ESCALATE = "escalate"
    INCONCLUSIVE = "inconclusive"


class HuntStatus(StrEnum):
    DRAFT = "draft"
    AWAITING_IOC_VALIDATION = "awaiting_ioc_validation"
    AWAITING_PLAN_VALIDATION = "awaiting_plan_validation"
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    CLOSED = "closed"
    INTERRUPTED = "interrupted"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Entity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    value: str


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10)
    severity: Severity
    confidence: Confidence
    entities: list[Entity] = Field(default_factory=list)
    evidence_query_ids: list[str] = Field(min_length=1)
    recorded_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @field_validator("evidence_query_ids")
    @classmethod
    def _no_empty_ids(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("a finding must cite at least one executed query")
        return cleaned


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    event: str
    source: str


class ExecutedQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query_id: str
    siem: str
    query: str
    executed_at: str
    returned_rows: int
    source_rows: int
    truncated: bool
    duration_ms: int
    intent: str | None = None
    columns: list[str] = Field(default_factory=list)
    sample: list[dict[str, Any]] = Field(default_factory=list)
    """Sample of the returned rows (at most ten), already minimized by the middleware and
    rehydrated for the analyst. The model has never seen this version."""
    model_sample: list[dict[str, Any]] = Field(default_factory=list)
    """The same rows as transmitted to the model (pseudonyms, masked)."""
    anonymization: dict[str, Any] = Field(default_factory=dict)
    interpretation: str | None = None
    """The agent's reading of this result, verbatim."""


class AttackTechnique(BaseModel):
    """MITRE ATT&CK technique the hunt sought to bring to light."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=600)


class AttackOverview(BaseModel):
    """Overview of the attack under investigation: what was being hunted and why.

    `description` and `techniques` come from the agent's conclusion (a proposal, like
    the verdict); `scope` is computed by the platform from the hunt's real parameters
    (time window, sources, budgets), never by the model.
    """

    model_config = ConfigDict(extra="forbid")

    description: str
    techniques: list[AttackTechnique] = Field(default_factory=list)
    scope: str


class PlaybookStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order: int = Field(ge=1)
    siem: str = Field(min_length=3, max_length=32)
    objective: str = Field(min_length=10, max_length=400)
    technique: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    expected_queries: int = Field(ge=1, le=30)


class Playbook(BaseModel):
    """Investigation plan proposed by the model, validated by the analyst before launch.

    The estimates are proposals; `validated_*` are the limits chosen by the analyst,
    the ones the middleware enforces.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    steps: list[PlaybookStep] = Field(default_factory=list)
    not_covered: str
    estimated_queries: int = Field(ge=1)
    estimated_iterations: int = Field(ge=1)
    instruction: str | None = None
    generated_at: str
    validated_by: str | None = None
    validated_at: str | None = None
    validated_queries: int | None = None
    validated_iterations: int | None = None

    def planned_by_siem(self) -> dict[str, int]:
        planned: dict[str, int] = {}
        for step in self.steps:
            planned[step.siem] = planned.get(step.siem, 0) + step.expected_queries
        return planned


class HumanDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    decided_by: str
    decided_at: str
    comment: str | None = None


class HuntReport(BaseModel):
    """End-of-hunt deliverable. The agent's verdict remains a proposal."""

    model_config = ConfigDict(extra="forbid")

    hunt_id: str
    hypothesis: str
    campaign: str | None = None
    analyst: str
    status: HuntStatus
    proposed_verdict: Verdict
    summary: str
    limitations: str
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    executed_queries: list[ExecutedQuery] = Field(default_factory=list)
    budgets: dict[str, Any] = Field(default_factory=dict)
    partial: bool = False
    interruption_reason: str | None = None
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    human_decision: HumanDecision | None = None
    attack_overview: AttackOverview | None = None
    playbook: Playbook | None = None
    parent_hunt_id: str | None = None
    recommendation: str | None = None
    sources: list[str] = Field(default_factory=list)
    investigation_window: str | None = None

    def findings_by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])

    def executed_by_siem(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for query in self.executed_queries:
            counts[query.siem] = counts.get(query.siem, 0) + 1
        return counts

    def observed_entities(self) -> list[tuple[Entity, list[Finding]]]:
        """Entities cited by the findings, with the findings that mention them, most
        cited first."""

        seen: dict[tuple[str, str], tuple[Entity, list[Finding]]] = {}
        for finding in self.findings_by_severity():
            for entity in finding.entities:
                key = (entity.type.lower(), entity.value)
                if key not in seen:
                    seen[key] = (entity, [])
                seen[key][1].append(finding)
        return sorted(seen.values(), key=lambda item: -len(item[1]))

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

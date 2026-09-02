"""Investigation dossier: the internal state of a hunt.

This is the only object the tools can write to, and that write is purely internal:
it has no effect on the SIEMs. Every addition is checked against the ledger of executed
queries, which makes the final report verifiable line by line.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from middleware.errors import ErrorCode, ToolError
from middleware.executor import QueryLedger
from middleware.guardrails.ioc import Ioc, IocStatus
from reporting.models import (
    AttackTechnique,
    Confidence,
    Entity,
    ExecutedQuery,
    Finding,
    HuntStatus,
    Playbook,
    Severity,
    TimelineEvent,
    Verdict,
)


@dataclass
class Conclusion:
    verdict: Verdict
    summary: str
    limitations: str
    timeline: list[TimelineEvent] = field(default_factory=list)
    attack_description: str | None = None
    techniques: list[AttackTechnique] = field(default_factory=list)
    recommendation: str | None = None


@dataclass
class Dossier:
    hunt_id: str
    hypothesis: str
    analyst: str
    campaign: str | None = None
    status: HuntStatus = HuntStatus.DRAFT
    iocs: list[Ioc] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    conclusion: Conclusion | None = None
    playbook: Playbook | None = None
    parent_hunt_id: str | None = None
    resume_context: str | None = None
    ioc_epoch: int = 0
    """Incremented on each indicator validation: a threat intelligence search still in
    flight at that moment is stale, its late results are discarded."""
    ledger: QueryLedger = field(default_factory=QueryLedger)
    interruption_reason: str | None = None

    @property
    def validated_iocs(self) -> list[Ioc]:
        return [ioc for ioc in self.iocs if ioc.status is IocStatus.VALIDATED]

    def add_finding(
        self,
        *,
        title: str,
        description: str,
        severity: Severity,
        confidence: Confidence,
        evidence_query_ids: list[str],
        entities: list[Entity] | None = None,
    ) -> Finding:
        unknown = self.ledger.unknown_ids(evidence_query_ids)
        if unknown:
            raise ToolError(
                ErrorCode.EVIDENCE_MISSING,
                f"Cited queries not found: {', '.join(unknown)}.",
                hint=(
                    "A finding must cite the identifier of a query actually executed "
                    "during this hunt."
                ),
            )

        finding = Finding(
            id=f"f_{uuid.uuid4().hex[:8]}",
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            entities=entities or [],
            evidence_query_ids=evidence_query_ids,
        )
        self.findings.append(finding)
        return finding

    def conclude(
        self,
        *,
        verdict: Verdict,
        summary: str,
        limitations: str,
        timeline: list[TimelineEvent] | None = None,
        attack_description: str | None = None,
        techniques: list[AttackTechnique] | None = None,
        recommendation: str | None = None,
    ) -> Conclusion:
        self.conclusion = Conclusion(
            verdict=verdict,
            summary=summary,
            limitations=limitations,
            timeline=timeline or [],
            attack_description=attack_description,
            techniques=list(techniques or []),
            recommendation=recommendation,
        )
        self.status = HuntStatus.AWAITING_REVIEW
        return self.conclusion

    def executed_queries(self) -> list[ExecutedQuery]:
        return [
            ExecutedQuery(
                query_id=record.query_id,
                siem=record.siem,
                query=record.query,
                executed_at=record.executed_at,
                returned_rows=record.returned_rows,
                source_rows=record.source_rows,
                truncated=record.truncated,
                duration_ms=record.duration_ms,
                intent=record.intent,
                columns=list(record.columns),
                sample=[dict(row) for row in record.sample],
                model_sample=[dict(row) for row in record.model_sample],
                anonymization=dict(record.anonymization),
                interpretation=record.interpretation,
            )
            for record in self.ledger.as_list()
        ]

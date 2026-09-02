"""Internal data repository.

The audit log has a single write operation: append. There is deliberately no method to
update or delete an event, even for an administrator: a modifiable log proves nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from middleware.audit import AuditEvent, AuditSink
from middleware.guardrails.ioc import Ioc, IocStatus
from reporting.dossier import Dossier
from reporting.models import Finding, HuntReport, HuntStatus, Verdict
from storage.models import (
    AuditRow,
    Base,
    CtiAnalysisRow,
    FindingRow,
    HuntRow,
    HuntStateRow,
    IocRow,
    QueryRow,
    ReportRow,
)


class Database:
    def __init__(self, url: str) -> None:
        self._engine = create_async_engine(url, future=True)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def create_all(self) -> None:
        await self._create_tables()
        await self._add_missing_columns()

    async def _add_missing_columns(self) -> None:
        """Minimal migration: `create_all` does not alter an existing table. Columns
        added over successive versions are created here, with a default value, so that a
        database already in service stays readable without any external tool."""

        expected = {
            "hunts": {
                "playbook": "JSON",
                "parent_hunt_id": "VARCHAR(64)",
                "resume_context": "TEXT",
            },
            "executed_queries": {
                "intent": "TEXT",
                "columns": "JSON DEFAULT '[]'",
                "sample": "JSON DEFAULT '[]'",
                "model_sample": "JSON DEFAULT '[]'",
                "anonymization": "JSON DEFAULT '{}'",
                "interpretation": "TEXT",
            },
        }
        async with self._engine.begin() as connection:
            for table, columns in expected.items():
                rows = await connection.execute(text(f"PRAGMA table_info({table})"))
                present = {row[1] for row in rows}
                for column, definition in columns.items():
                    if column not in present:
                        await connection.execute(
                            text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                        )

    async def _create_tables(self) -> None:
        async with self._engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self._engine.dispose()

    def session(self) -> AsyncSession:
        return self._session_factory()


class SqlAuditSink(AuditSink):
    """Persistent audit sink. Write-only."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def write(self, event: AuditEvent) -> None:
        async with self._database.session() as session:
            session.add(
                AuditRow(
                    hunt_id=event.hunt_id,
                    type=event.type.value,
                    actor=event.actor,
                    timestamp=event.timestamp,
                    siem=event.siem,
                    query_id=event.query_id,
                    query=event.query,
                    rows_returned=event.rows_returned,
                    truncated=event.truncated,
                    duration_ms=event.duration_ms,
                    error_code=event.error_code,
                    detail=event.detail,
                )
            )
            await session.commit()


class HuntRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def create_hunt(self, dossier: Dossier) -> None:
        async with self._database.session() as session:
            session.add(
                HuntRow(
                    id=dossier.hunt_id,
                    hypothesis=dossier.hypothesis,
                    campaign=dossier.campaign,
                    analyst=dossier.analyst,
                    status=dossier.status.value,
                    parent_hunt_id=dossier.parent_hunt_id,
                    resume_context=dossier.resume_context,
                )
            )
            await session.commit()

    async def set_status(
        self,
        hunt_id: str,
        status: HuntStatus,
        *,
        interruption_reason: str | None = None,
    ) -> None:
        async with self._database.session() as session:
            hunt = await session.get(HuntRow, hunt_id)
            if hunt is None:
                return
            hunt.status = status.value
            if interruption_reason is not None:
                hunt.interruption_reason = interruption_reason
            await session.commit()

    async def save_hunt_state(self, hunt_id: str, payload: dict[str, Any]) -> None:
        async with self._database.session() as session:
            existing = await session.get(HuntStateRow, hunt_id)
            if existing is None:
                session.add(HuntStateRow(hunt_id=hunt_id, payload=payload))
            else:
                existing.payload = payload
            await session.commit()

    async def load_hunt_state(self, hunt_id: str) -> dict[str, Any] | None:
        async with self._database.session() as session:
            row = await session.get(HuntStateRow, hunt_id)
            return dict(row.payload) if row else None

    async def delete_hunt_state(self, hunt_id: str) -> None:
        async with self._database.session() as session:
            row = await session.get(HuntStateRow, hunt_id)
            if row is not None:
                await session.delete(row)
                await session.commit()

    async def set_playbook(self, hunt_id: str, playbook: dict[str, Any] | None) -> None:
        async with self._database.session() as session:
            hunt = await session.get(HuntRow, hunt_id)
            if hunt is None:
                return
            hunt.playbook = playbook
            await session.commit()

    async def mark_running_as_interrupted(self, reason: str) -> int:
        """At startup: a hunt still marked "running" in the database no longer has a loop
        in memory, so it is marked interrupted rather than lingering as a zombie in the
        lists."""

        async with self._database.session() as session:
            rows = await session.execute(
                select(HuntRow).where(HuntRow.status == HuntStatus.RUNNING.value)
            )
            hunts = list(rows.scalars())
            for hunt in hunts:
                hunt.status = HuntStatus.INTERRUPTED.value
                hunt.interruption_reason = reason
            await session.commit()
            return len(hunts)

    async def replace_iocs(self, hunt_id: str, iocs: list[Ioc]) -> None:
        async with self._database.session() as session:
            existing = await session.execute(select(IocRow).where(IocRow.hunt_id == hunt_id))
            for row in existing.scalars():
                await session.delete(row)
            for ioc in iocs:
                session.add(
                    IocRow(
                        hunt_id=hunt_id,
                        value=ioc.value,
                        type=ioc.type.value,
                        source_name=ioc.source_name,
                        source_url=ioc.source_url,
                        first_seen=ioc.first_seen,
                        confidence=ioc.confidence,
                        status=ioc.status.value,
                        validated_by=ioc.validated_by,
                        validated_at=ioc.validated_at,
                    )
                )
            await session.commit()

    async def load_iocs(self, hunt_id: str) -> list[Ioc]:
        async with self._database.session() as session:
            rows = await session.execute(select(IocRow).where(IocRow.hunt_id == hunt_id))
            return [
                Ioc(
                    value=row.value,
                    type=row.type,
                    source_name=row.source_name,
                    source_url=row.source_url,
                    first_seen=row.first_seen,
                    confidence=row.confidence,
                    status=IocStatus(row.status),
                    validated_by=row.validated_by,
                    validated_at=row.validated_at,
                )
                for row in rows.scalars()
            ]

    async def save_report(self, report: HuntReport) -> None:
        async with self._database.session() as session:
            for query in report.executed_queries:
                if await session.get(QueryRow, query.query_id) is None:
                    session.add(QueryRow(hunt_id=report.hunt_id, **query.model_dump()))
            for finding in report.findings:
                if await session.get(FindingRow, finding.id) is None:
                    session.add(_finding_row(report.hunt_id, finding))

            existing = await session.get(ReportRow, report.hunt_id)
            payload = report.model_dump(mode="json")
            if existing is None:
                session.add(
                    ReportRow(
                        hunt_id=report.hunt_id,
                        payload=payload,
                        proposed_verdict=report.proposed_verdict.value,
                        partial=report.partial,
                        generated_at=report.generated_at,
                    )
                )
            else:
                existing.payload = payload
                existing.proposed_verdict = report.proposed_verdict.value
                existing.partial = report.partial
                existing.generated_at = report.generated_at

            hunt = await session.get(HuntRow, report.hunt_id)
            if hunt is not None:
                hunt.status = report.status.value
                hunt.interruption_reason = report.interruption_reason
            await session.commit()

    async def load_report(self, hunt_id: str) -> HuntReport | None:
        async with self._database.session() as session:
            row = await session.get(ReportRow, hunt_id)
            if row is None:
                return None
            report = HuntReport.model_validate(row.payload)
            if row.human_verdict:
                report.human_decision = _decision(row)
            return report

    async def record_decision(
        self,
        hunt_id: str,
        *,
        verdict: Verdict,
        decided_by: str,
        comment: str | None,
    ) -> bool:
        """Records the human verdict. The agent's verdict is kept unchanged."""

        async with self._database.session() as session:
            row = await session.get(ReportRow, hunt_id)
            if row is None:
                return False
            row.human_verdict = verdict.value
            row.decided_by = decided_by
            row.decided_at = datetime.now(UTC).isoformat()
            row.decision_comment = comment
            hunt = await session.get(HuntRow, hunt_id)
            if hunt is not None:
                hunt.status = HuntStatus.CLOSED.value
            await session.commit()
            return True

    async def delete_hunt(self, hunt_id: str) -> bool:
        """Deletes a hunt's operational data: dossier, IOCs, queries, findings, report. The
        audit log (`AuditRow`) is deliberately preserved: it is append-only and remains
        admissible, even for a deleted hunt."""

        async with self._database.session() as session:
            hunt = await session.get(HuntRow, hunt_id)
            report = await session.get(ReportRow, hunt_id)
            if hunt is None and report is None:
                return False
            for model in (IocRow, QueryRow, FindingRow):
                await session.execute(delete(model).where(model.hunt_id == hunt_id))
            await session.execute(delete(ReportRow).where(ReportRow.hunt_id == hunt_id))
            await session.execute(delete(HuntRow).where(HuntRow.id == hunt_id))
            await session.commit()
            return True

    async def list_hunts(
        self,
        *,
        analyst: str | None = None,
        status: HuntStatus | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        async with self._database.session() as session:
            statement = select(HuntRow).order_by(HuntRow.created_at.desc()).limit(limit)
            if analyst:
                statement = statement.where(HuntRow.analyst == analyst)
            if status:
                statement = statement.where(HuntRow.status == status.value)
            rows = await session.execute(statement)
            return [_hunt_summary(row) for row in rows.scalars()]

    async def get_hunt(self, hunt_id: str) -> dict[str, Any] | None:
        async with self._database.session() as session:
            row = await session.get(HuntRow, hunt_id)
            return _hunt_summary(row) if row else None

    async def save_cti_analysis(
        self,
        *,
        analysis_id: str,
        filename: str,
        analyzed_by: str,
        analyzed_at: str,
        pages: int,
        truncated: bool,
        attacks: list[dict[str, Any]],
    ) -> None:
        async with self._database.session() as session:
            session.add(
                CtiAnalysisRow(
                    id=analysis_id,
                    filename=filename,
                    analyzed_by=analyzed_by,
                    analyzed_at=analyzed_at,
                    pages=pages,
                    truncated=truncated,
                    payload={"attacks": attacks},
                )
            )
            await session.commit()

    async def set_cti_probe(
        self, analysis_id: str, attack_index: int, probe: dict[str, Any]
    ) -> None:
        """Attaches a probe result to the corresponding attack in the analysis."""

        async with self._database.session() as session:
            row = await session.get(CtiAnalysisRow, analysis_id)
            if row is None:
                return
            payload = dict(row.payload or {})
            attacks = list(payload.get("attacks", []))
            if 0 <= attack_index < len(attacks):
                attacks[attack_index] = {**attacks[attack_index], "probe": probe}
                row.payload = {**payload, "attacks": attacks}
                await session.commit()

    async def cti_history(self, limit: int = 20) -> list[dict[str, Any]]:
        async with self._database.session() as session:
            rows = await session.execute(
                select(CtiAnalysisRow).order_by(CtiAnalysisRow.analyzed_at.desc()).limit(limit)
            )
            entries: list[dict[str, Any]] = []
            for row in rows.scalars():
                attacks = (row.payload or {}).get("attacks", [])
                entries.append(
                    {
                        "id": row.id,
                        "filename": row.filename,
                        "analyzed_by": row.analyzed_by,
                        "analyzed_at": row.analyzed_at,
                        "attacks": len(attacks),
                        "iocs": sum(len(a.get("iocs", [])) for a in attacks),
                        "pages": row.pages,
                    }
                )
            return entries

    async def get_cti_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        async with self._database.session() as session:
            row = await session.get(CtiAnalysisRow, analysis_id)
            if row is None:
                return None
            return {
                "analysis_id": row.id,
                "filename": row.filename,
                "analyzed_by": row.analyzed_by,
                "analyzed_at": row.analyzed_at,
                "pages": row.pages,
                "truncated": row.truncated,
                "attacks": (row.payload or {}).get("attacks", []),
            }

    async def delete_cti_analysis(self, analysis_id: str) -> bool:
        async with self._database.session() as session:
            row = await session.get(CtiAnalysisRow, analysis_id)
            if row is None:
                return False
            await session.delete(row)
            await session.commit()
            return True

    async def audit_trail(self, hunt_id: str) -> list[dict[str, Any]]:
        async with self._database.session() as session:
            rows = await session.execute(
                select(AuditRow).where(AuditRow.hunt_id == hunt_id).order_by(AuditRow.id)
            )
            return [
                {
                    "id": row.id,
                    "type": row.type,
                    "actor": row.actor,
                    "timestamp": row.timestamp,
                    "siem": row.siem,
                    "query_id": row.query_id,
                    "query": row.query,
                    "rows_returned": row.rows_returned,
                    "truncated": row.truncated,
                    "duration_ms": row.duration_ms,
                    "error_code": row.error_code,
                    "detail": row.detail,
                }
                for row in rows.scalars()
            ]

    async def dashboard(self, *, limit: int = 20) -> dict[str, Any]:
        async with self._database.session() as session:
            hunts = (
                (
                    await session.execute(
                        select(HuntRow).order_by(HuntRow.created_at.desc()).limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            findings = (await session.execute(select(FindingRow))).scalars().all()
            queries = (await session.execute(select(QueryRow))).scalars().all()

        severity_counts: dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        entity_counts: dict[str, int] = {}
        for finding in findings:
            for entity in finding.entities or []:
                key = f"{entity.get('type')}:{entity.get('value')}"
                entity_counts[key] = entity_counts.get(key, 0) + 1

        siem_counts: dict[str, int] = {}
        for query in queries:
            siem_counts[query.siem] = siem_counts.get(query.siem, 0) + 1

        return {
            "recent_hunts": [_hunt_summary(hunt) for hunt in hunts],
            "findings_by_severity": severity_counts,
            "top_entities": sorted(
                ({"entity": key, "count": count} for key, count in entity_counts.items()),
                key=lambda item: item["count"],
                reverse=True,
            )[:10],
            "queries_by_siem": siem_counts,
        }

    async def iter_hunt_ids(self) -> AsyncIterator[str]:
        async with self._database.session() as session:
            rows = await session.execute(select(HuntRow.id))
            for value in rows.scalars():
                yield value


def _finding_row(hunt_id: str, finding: Finding) -> FindingRow:
    return FindingRow(
        id=finding.id,
        hunt_id=hunt_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        entities=[entity.model_dump() for entity in finding.entities],
        evidence_query_ids=finding.evidence_query_ids,
        recorded_at=finding.recorded_at,
    )


def _hunt_summary(row: HuntRow) -> dict[str, Any]:
    return {
        "hunt_id": row.id,
        "hypothesis": row.hypothesis,
        "campaign": row.campaign,
        "analyst": row.analyst,
        "status": row.status,
        "created_at": row.created_at.isoformat(),
        "interruption_reason": row.interruption_reason,
        "playbook": row.playbook,
        "parent_hunt_id": row.parent_hunt_id,
        "resume_context": row.resume_context,
    }


def _decision(row: ReportRow) -> Any:
    from reporting.models import HumanDecision

    return HumanDecision(
        verdict=Verdict(row.human_verdict),
        decided_by=row.decided_by or "unknown",
        decided_at=row.decided_at or "",
        comment=row.decision_comment,
    )

"""Internal database schema.

The audit log is append-only: the repository exposes no method to update or delete an
event. That is what makes the audit screen admissible during a review.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class HuntRow(Base):
    __tablename__ = "hunts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hypothesis: Mapped[str] = mapped_column(Text)
    campaign: Mapped[str | None] = mapped_column(String(200), nullable=True)
    analyst: Mapped[str] = mapped_column(String(200), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    interruption_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    playbook: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    parent_hunt_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resume_context: Mapped[str | None] = mapped_column(Text, nullable=True)

    iocs: Mapped[list[IocRow]] = relationship(back_populates="hunt", cascade="all, delete-orphan")
    queries: Mapped[list[QueryRow]] = relationship(
        back_populates="hunt", cascade="all, delete-orphan"
    )
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="hunt", cascade="all, delete-orphan"
    )


class IocRow(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hunt_id: Mapped[str] = mapped_column(ForeignKey("hunts.id"), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    type: Mapped[str] = mapped_column(String(32))
    source_name: Mapped[str] = mapped_column(String(200))
    source_url: Mapped[str] = mapped_column(String(2048))
    first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    validated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    validated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    hunt: Mapped[HuntRow] = relationship(back_populates="iocs")


class QueryRow(Base):
    __tablename__ = "executed_queries"

    query_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hunt_id: Mapped[str] = mapped_column(ForeignKey("hunts.id"), index=True)
    siem: Mapped[str] = mapped_column(String(32), index=True)
    query: Mapped[str] = mapped_column(Text)
    executed_at: Mapped[str] = mapped_column(String(64))
    returned_rows: Mapped[int] = mapped_column(Integer)
    source_rows: Mapped[int] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    intent: Mapped[str | None] = mapped_column(Text, nullable=True)
    columns: Mapped[list[str]] = mapped_column(JSON, default=list)
    sample: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    model_sample: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    anonymization: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    interpretation: Mapped[str | None] = mapped_column(Text, nullable=True)

    hunt: Mapped[HuntRow] = relationship(back_populates="queries")


class HuntStateRow(Base):
    """Execution state of a running or interrupted hunt: tokenized transcript, pseudonym
    table, consumed budgets, query registry, findings. Saved at each iteration, purged at
    conclusion — this is what allows an interrupted loop to be continued exactly where it
    stopped. Never leaves the internal database."""

    __tablename__ = "hunt_states"

    hunt_id: Mapped[str] = mapped_column(
        ForeignKey("hunts.id", ondelete="CASCADE"), primary_key=True
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hunt_id: Mapped[str] = mapped_column(ForeignKey("hunts.id"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    entities: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence_query_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    recorded_at: Mapped[str] = mapped_column(String(64))

    hunt: Mapped[HuntRow] = relationship(back_populates="findings")


class AuditRow(Base):
    """Append-only log. No modification method exists in the repository."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hunt_id: Mapped[str] = mapped_column(String(64), index=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    actor: Mapped[str] = mapped_column(String(200), index=True)
    timestamp: Mapped[str] = mapped_column(String(64), index=True)
    siem: Mapped[str | None] = mapped_column(String(32), nullable=True)
    query_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    rows_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    truncated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ReportRow(Base):
    __tablename__ = "reports"

    hunt_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    proposed_verdict: Mapped[str] = mapped_column(String(32), index=True)
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    generated_at: Mapped[str] = mapped_column(String(64))
    human_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_comment: Mapped[str | None] = mapped_column(Text, nullable=True)


class CtiAnalysisRow(Base):
    """Analysis of a CTI report, persisted with its results (attacks and probes) so it can
    be restored from history. Deletable by the analyst: the immutable trace of the
    analysis itself stays in the audit log."""

    __tablename__ = "cti_analyses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    analyzed_by: Mapped[str] = mapped_column(String(200), index=True)
    analyzed_at: Mapped[str] = mapped_column(String(64))
    pages: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class UserRow(Base):
    """Local account created by an admin. Never self-registration: access is granted."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(200), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    roles: Mapped[str] = mapped_column(String(200))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

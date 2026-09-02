"""Hunt audit log.

Traces everything that must be showable during a review: queries actually executed,
volumes returned, agent decisions, human validations and their author. The log is
write-only on the application side: no API modifies or deletes it.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class AuditEventType(StrEnum):
    HUNT_CREATED = "hunt_created"
    IOC_SEARCH = "ioc_search"
    IOC_VALIDATION = "ioc_validation"
    IOC_IMPORT = "ioc_import"
    PLAN_PROPOSED = "plan_proposed"
    PLAN_VALIDATED = "plan_validated"
    QUERY_EXECUTED = "query_executed"
    QUERY_REJECTED = "query_rejected"
    ANONYMIZATION_DEGRADED = "anonymization_degraded"
    AGENT_DECISION = "agent_decision"
    FINDING_RECORDED = "finding_recorded"
    BUDGET_EVENT = "budget_event"
    HUNT_CONCLUDED = "hunt_concluded"
    HUNT_INTERRUPTED = "hunt_interrupted"
    HUNT_RESUMED = "hunt_resumed"
    HUNT_CONTINUED = "hunt_continued"
    HUNT_DELETED = "hunt_deleted"
    REPORT_VALIDATED = "report_validated"
    CONFIG_SECRET_UPDATED = "config_secret_updated"  # noqa: S105 - event name
    CONFIG_SECRET_DELETED = "config_secret_deleted"  # noqa: S105 - event name
    CONFIG_SOURCE_TESTED = "config_source_tested"
    CONFIG_ACCOUNT_CREATED = "config_account_created"
    CONFIG_ACCOUNT_DELETED = "config_account_deleted"
    ACCOUNT_PASSWORD_CHANGED = "account_password_changed"  # noqa: S105 - event name
    CTI_REPORT_ANALYZED = "cti_report_analyzed"
    CTI_REPORT_DELETED = "cti_report_deleted"
    AUTH_LOGIN = "auth_login"
    AUTH_LOGIN_FAILED = "auth_login_failed"


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    hunt_id: str
    type: AuditEventType
    actor: str
    timestamp: str = field(default_factory=_utcnow)
    siem: str | None = None
    query_id: str | None = None
    query: str | None = None
    rows_returned: int | None = None
    truncated: bool | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["type"] = self.type.value
        return payload


class AuditSink(ABC):
    @abstractmethod
    async def write(self, event: AuditEvent) -> None: ...


class MemoryAuditSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class JsonlAuditSink(AuditSink):
    """Development sink. In production, the sink is the internal database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def write(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")


class AuditJournal:
    """Facade used by the middleware and the orchestrator."""

    def __init__(self, sink: AuditSink, *, hunt_id: str, actor: str) -> None:
        self._sink = sink
        self._hunt_id = hunt_id
        self._actor = actor
        self._listeners: list[Callable[[AuditEvent], None]] = []

    @property
    def hunt_id(self) -> str:
        return self._hunt_id

    def subscribe(self, listener: Callable[[AuditEvent], None]) -> None:
        """Wires the front's real-time stream onto the log."""

        self._listeners.append(listener)

    async def record(self, event_type: AuditEventType, **fields: Any) -> AuditEvent:
        event = AuditEvent(
            hunt_id=self._hunt_id,
            type=event_type,
            actor=fields.pop("actor", self._actor),
            **fields,
        )
        await self._sink.write(event)
        for listener in self._listeners:
            listener(event)
        return event

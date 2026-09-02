"""Contracts of the internal API consumed by the front end.

The front end only receives data already minimized and never sees an internal
technical identifier: neither a real workspace name, nor an endpoint, nor a service identity.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from middleware.guardrails.ioc import IocType
from reporting.models import Verdict


class ManualIocInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=2048)
    type: IocType
    note: str | None = None


class CreateHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis: str | None = Field(default=None, min_length=10, max_length=4000)
    campaign: str | None = Field(default=None, min_length=2, max_length=120)
    manual_iocs: list[ManualIocInput] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    max_iterations: int | None = Field(default=None, ge=1, le=100)
    max_siem_queries: int | None = Field(default=None, ge=1, le=100)
    window_start: str | None = None
    """Start of the enforced investigation period (ISO 8601 with timezone). Optional:
    by default, the agent picks its windows within the per-source caps."""
    window_end: str | None = None
    """End of the period. Optional if a start is given (default: now)."""

    @model_validator(mode="after")
    def _require_starting_point(self) -> CreateHuntRequest:
        """A hunt starts either from a hypothesis, or from a campaign or actor.

        The "one or the other" rule lives in the code, not just in the UI:
        a request without a starting point is rejected before any hunt is created.
        """
        if not self.hypothesis and not self.campaign:
            raise ValueError(
                "A hunt starts either from a hypothesis, or from a campaign or actor."
            )
        return self

    @model_validator(mode="after")
    def _window_is_coherent(self) -> CreateHuntRequest:
        if self.window_end and not self.window_start:
            raise ValueError("An end of period without a start makes no sense.")
        if self.window_start:
            start = _parse_aware_iso(self.window_start, "window_start")
            if self.window_end:
                end = _parse_aware_iso(self.window_end, "window_end")
                if end <= start:
                    raise ValueError("The end of period must be later than the start.")
        return self


def _parse_aware_iso(value: str, label: str) -> Any:
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid ISO 8601 date.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must carry a timezone (Z suffix for UTC).")
    return parsed


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str | None = Field(default=None, max_length=1500)
    """Free-form instruction from the analyst to steer or reformulate the plan."""


class StartHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_iterations: int | None = Field(default=None, ge=1, le=100)
    max_siem_queries: int | None = Field(default=None, ge=1, le=100)
    """Budgets chosen by the analyst. By default, those estimated by the validated playbook."""


class ResumeHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str | None = Field(default=None, max_length=1500)
    """Question or instruction from the analyst for the resumption."""
    from_query_id: str | None = Field(default=None, pattern=r"^q_[0-9a-f]{6,16}$")
    """Resume after this query of the original hunt; by default, after the last one."""


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1, max_length=200)


class HuntCreated(BaseModel):
    hunt_id: str
    status: str
    requires_ioc_validation: bool


class IocView(BaseModel):
    value: str
    type: str
    source: str
    source_url: str
    corroborating_sources: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    confidence: str | None = None
    status: str


class EnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_name: str = Field(min_length=2, max_length=120)
    ioc_types: list[IocType] | None = None
    max_results: int = Field(default=50, ge=1, le=200)
    time_range: Literal["month", "3months", "9months", "year"] | None = None


class AddIocsRequest(BaseModel):
    """Indicators added manually by the analyst on the validation screen."""

    model_config = ConfigDict(extra="forbid")

    iocs: list[ManualIocInput] = Field(min_length=1, max_length=200)


class ValidateIocsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validated: list[str] = Field(default_factory=list)
    rejected: list[str] = Field(default_factory=list)


class BudgetDecisionRequest(BaseModel):
    """Analyst's response to the budget checkpoint of a paused hunt."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["extend", "stop"]
    extra_iterations: int = Field(default=0, ge=0, le=100)
    extra_siem_queries: int = Field(default=0, ge=0, le=100)
    extra_minutes: int = Field(default=0, ge=0, le=60)

    @model_validator(mode="after")
    def _extension_is_not_empty(self) -> BudgetDecisionRequest:
        if self.action == "extend" and not (
            self.extra_iterations or self.extra_siem_queries or self.extra_minutes
        ):
            raise ValueError("An extension must grant at least one supplement.")
        return self


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    comment: str | None = Field(default=None, max_length=4000)


class SourceLimits(BaseModel):
    """Real per-source limits, shown to the analyst rather than silently imposed."""

    name: str
    max_window_days: int
    max_rows: int
    configured: bool
    note: str | None = None


class PlatformConfig(BaseModel):
    sources: list[SourceLimits]
    budgets: dict[str, Any]
    threat_intel_enabled: bool
    workspaces: list[str]
    demo_siem: bool = False


class SecretFieldView(BaseModel):
    """State of a key, never its value. This is all the browser can know."""

    name: str
    configured: bool
    origin: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None


class SourceConfigView(BaseModel):
    """State of a connector in the Configuration screen."""

    id: str
    label: str
    kind: str
    active: bool
    secrets: list[SecretFieldView]
    requirement: str | None = None


class SecretUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=4, max_length=4096)


class SourceTestResult(BaseModel):
    source: str
    ok: bool
    detail: str


class CtiIocView(BaseModel):
    value: str
    type: str


class CtiAttackView(BaseModel):
    """An attack described in an imported CTI report, with the proposed hunt
    approach. The analyst reviews and adjusts it in the form before any creation."""

    name: str
    kind: str
    summary: str
    approach: str
    suggested_hypothesis: str = ""
    iocs: list[CtiIocView] = Field(default_factory=list)


class CtiAnalysisView(BaseModel):
    analysis_id: str
    attacks: list[CtiAttackView]
    pages: int
    truncated: bool


class CtiProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_name: str = Field(min_length=2, max_length=120)
    analysis_id: str | None = Field(default=None, max_length=64)
    attack_index: int | None = Field(default=None, ge=0, le=20)


class CtiProbeView(BaseModel):
    """Availability of threat intelligence IOCs for a threat, before hunt creation."""

    found: int
    sources: list[str]
    sample: list[CtiIocView]


class CtiHistoryEntry(BaseModel):
    id: str
    filename: str
    analyzed_by: str
    analyzed_at: str
    attacks: int
    iocs: int
    pages: int


class CtiAttackStoredView(CtiAttackView):
    probe: CtiProbeView | None = None


class CtiStoredAnalysisView(BaseModel):
    """Analysis restored from history, with the probes already performed."""

    analysis_id: str
    filename: str
    analyzed_by: str
    analyzed_at: str
    pages: int
    truncated: bool
    attacks: list[CtiAttackStoredView]


_ACCOUNT_ROLES = {"analyst", "reader", "admin"}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=1, max_length=1024)


class SessionView(BaseModel):
    name: str
    roles: list[str]


class CreateAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=2, max_length=200, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    password: str = Field(min_length=12, max_length=1024)
    roles: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _roles_are_known(self) -> CreateAccountRequest:
        unknown = set(self.roles) - _ACCOUNT_ROLES
        if unknown:
            raise ValueError(f"Unknown roles: {', '.join(sorted(unknown))}")
        return self


class AccountView(BaseModel):
    username: str
    roles: list[str]
    created_by: str
    created_at: str

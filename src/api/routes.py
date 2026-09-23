"""Internal API routes.

The two human checkpoints are distinct routes, reserved for the analyst role and
logged by name: indicator validation before any querying, verdict validation before
any decision.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse

from api.accounts import MIN_PASSWORD_LENGTH, SESSION_COOKIE
from api.auth import Principal, current_principal, require_admin, require_analyst
from api.runtime import HuntRuntime
from api.schemas import (
    AccountView,
    AddIocsRequest,
    BudgetDecisionRequest,
    ChangePasswordRequest,
    CreateAccountRequest,
    CreateHuntRequest,
    CtiAnalysisView,
    CtiHistoryEntry,
    CtiProbeRequest,
    CtiProbeView,
    CtiStoredAnalysisView,
    DecisionRequest,
    EnrichRequest,
    HuntCreated,
    IocView,
    LoginRequest,
    PlanRequest,
    PlatformConfig,
    ResumeHuntRequest,
    SecretUpdateRequest,
    SessionView,
    SourceConfigView,
    SourceLimits,
    SourceTestResult,
    StartHuntRequest,
    ValidateIocsRequest,
)
from middleware.audit import AuditEventType
from middleware.errors import ToolError
from middleware.guardrails.ioc import Ioc, summarize_for_model
from reporting.models import HuntStatus, Verdict
from reporting.pdf import to_pdf
from reporting.report import to_markdown
from storage.repository import HuntRepository

router = APIRouter(prefix="/api")


def _runtime(request: Request) -> HuntRuntime:
    return request.app.state.runtime


def _repository(request: Request) -> HuntRepository:
    return request.app.state.repository


def _http_error(error: ToolError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": error.code.value, "message": error.message, "hint": error.hint},
    )


def _ioc_views(iocs: list[Ioc]) -> list[IocView]:
    return [IocView(**item) for item in summarize_for_model(iocs)]


@router.get("/config", response_model=PlatformConfig)
async def platform_config(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> PlatformConfig:
    runtime = _runtime(request)
    settings = runtime.settings
    available = runtime.available_sources

    return PlatformConfig(
        sources=[
            SourceLimits(
                name="sentinel",
                max_window_days=settings.sentinel.window_days_max,
                max_rows=settings.sentinel.rows_max,
                configured="sentinel" in available,
            ),
            SourceLimits(
                name="defender",
                max_window_days=settings.defender.window_days_max,
                max_rows=settings.defender.rows_max,
                configured="defender" in available,
                note="The Defender API only returns the last 30 days.",
            ),
            SourceLimits(
                name="secops",
                max_window_days=settings.secops.window_days_max,
                max_rows=settings.secops.rows_max,
                configured="secops" in available,
            ),
        ],
        budgets=settings.budgets.model_dump(),
        threat_intel_enabled=runtime.threat_intel_enabled,
        workspaces=sorted(settings.workspace_aliases),
        demo_siem=settings.demo_siem,
    )


def _accounts(request: Request) -> Any:
    accounts = getattr(request.app.state, "accounts", None)
    if accounts is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Local accounts are unavailable on this installation.",
        )
    return accounts


def _sessions(request: Request) -> Any:
    sessions = getattr(request.app.state, "sessions", None)
    if sessions is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sessions are unavailable on this installation.",
        )
    return sessions


@router.post("/auth/login", response_model=SessionView)
async def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
) -> SessionView:
    """Login via local account. Failure is slowed and logged, success too."""

    accounts = _accounts(request)
    sessions = _sessions(request)
    username = payload.username.strip()

    principal = await accounts.authenticate(username, payload.password)
    if principal is None:
        await _runtime(request).record_platform_event(
            AuditEventType.AUTH_LOGIN_FAILED, actor=username, detail={}
        )
        await asyncio.sleep(0.5)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    response.set_cookie(
        SESSION_COOKIE,
        sessions.issue(principal),
        httponly=True,
        secure=_runtime(request).settings.environment != "dev",
        samesite="lax",
        max_age=sessions.max_age_seconds,
        path="/",
    )
    await _runtime(request).record_platform_event(
        AuditEventType.AUTH_LOGIN, actor=principal.name, detail={}
    )
    return SessionView(name=principal.name, roles=sorted(principal.roles))


@router.post("/auth/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_own_password(
    request: Request,
    payload: ChangePasswordRequest,
    principal: Principal = Depends(current_principal),
) -> None:
    """Every user can change their own password, whatever their role.
    The current password is required (a stolen session is not enough), and the change
    is logged - never the value."""

    accounts = _accounts(request)
    if await accounts.authenticate(principal.name, payload.current_password) is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password incorrect.",
        )
    if len(payload.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"The new password must be at least {MIN_PASSWORD_LENGTH} characters.",
        )
    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The new password must differ from the current one.",
        )
    await accounts.set_password(principal.name, payload.new_password)
    await _runtime(request).record_platform_event(
        AuditEventType.ACCOUNT_PASSWORD_CHANGED,
        actor=principal.name,
        detail={"username": principal.name},
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/auth/me", response_model=SessionView)
async def whoami(principal: Principal = Depends(current_principal)) -> SessionView:
    return SessionView(name=principal.name, roles=sorted(principal.roles))


@router.get("/config/accounts", response_model=list[AccountView])
async def list_accounts(
    request: Request,
    principal: Principal = Depends(require_admin),
) -> list[AccountView]:
    rows = await _accounts(request).list_accounts()
    return [
        AccountView(
            username=row["username"],
            roles=[role for role in row["roles"].split(",") if role],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@router.post("/config/accounts", status_code=status.HTTP_201_CREATED)
async def create_account(
    request: Request,
    payload: CreateAccountRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, str]:
    try:
        await _accounts(request).create(
            username=payload.username,
            password=payload.password,
            roles=payload.roles,
            created_by=principal.name,
        )
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    await _runtime(request).record_platform_event(
        AuditEventType.CONFIG_ACCOUNT_CREATED,
        actor=principal.name,
        detail={"username": payload.username, "roles": sorted(set(payload.roles))},
    )
    return {"username": payload.username}


@router.delete("/config/accounts/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    request: Request,
    username: str,
    principal: Principal = Depends(require_admin),
) -> None:
    accounts = _accounts(request)
    rows = await accounts.list_accounts()
    target = next((row for row in rows if row["username"] == username), None)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown account.")
    if "admin" in target["roles"].split(",") and await accounts.count_admins() <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the last admin account.",
        )
    await accounts.delete(username)
    await _runtime(request).record_platform_event(
        AuditEventType.CONFIG_ACCOUNT_DELETED,
        actor=principal.name,
        detail={"username": username},
    )


@router.get("/config/sources", response_model=list[SourceConfigView])
async def source_configuration(
    request: Request,
    principal: Principal = Depends(require_admin),
) -> list[SourceConfigView]:
    """Connector states for the Configuration screen. No key value leaves here."""

    try:
        return _runtime(request).describe_sources()
    except ToolError as error:
        raise _http_error(error) from error


@router.put("/config/secrets/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def update_secret(
    request: Request,
    name: str,
    payload: SecretUpdateRequest,
    principal: Principal = Depends(require_admin),
) -> None:
    """Write-only: the key goes in, it will never come back out through the API."""

    try:
        await _runtime(request).update_secret(name, payload.value, actor=principal.name)
    except ToolError as error:
        raise _http_error(error) from error


@router.delete("/config/secrets/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    request: Request,
    name: str,
    principal: Principal = Depends(require_admin),
) -> None:
    try:
        removed = await _runtime(request).delete_secret(name, actor=principal.name)
    except ToolError as error:
        raise _http_error(error) from error
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This key is not in the configuration store.",
        )


@router.post("/config/sources/{source_id}/test", response_model=SourceTestResult)
async def test_source(
    request: Request,
    source_id: str,
    principal: Principal = Depends(require_admin),
) -> SourceTestResult:
    try:
        return await _runtime(request).test_source(source_id, actor=principal.name)
    except ToolError as error:
        raise _http_error(error) from error


@router.post("/hunts", response_model=HuntCreated, status_code=status.HTTP_201_CREATED)
async def create_hunt(
    request: Request,
    payload: CreateHuntRequest,
    principal: Principal = Depends(require_analyst),
) -> HuntCreated:
    hunt = await _runtime(request).create(payload, analyst=principal.name)
    return HuntCreated(
        hunt_id=hunt.dossier.hunt_id,
        status=hunt.dossier.status.value,
        requires_ioc_validation=hunt.dossier.status is HuntStatus.AWAITING_IOC_VALIDATION,
    )


@router.get("/hunts")
async def list_hunts(
    request: Request,
    principal: Principal = Depends(current_principal),
    analyst: str | None = None,
    hunt_status: HuntStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    return await _repository(request).list_hunts(analyst=analyst, status=hunt_status, limit=limit)


@router.post("/hunts/{hunt_id}/enrich", response_model=list[IocView])
async def enrich_hunt(
    request: Request,
    hunt_id: str,
    payload: EnrichRequest,
    principal: Principal = Depends(require_analyst),
) -> list[IocView]:
    try:
        iocs = await _runtime(request).enrich(
            hunt_id,
            campaign_name=payload.campaign_name,
            ioc_types=payload.ioc_types,
            max_results=payload.max_results,
            time_range=payload.time_range,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return _ioc_views(iocs)


@router.post("/hunts/{hunt_id}/iocs")
async def add_manual_iocs(
    request: Request,
    hunt_id: str,
    payload: AddIocsRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Indicators added by the analyst before launch, in addition to threat
    intelligence. Their source is the analyst themselves, by name. An indicator
    already present (normalized defang) is not added: it is flagged."""

    try:
        outcome = await _runtime(request).add_manual_iocs(
            hunt_id, items=payload.iocs, analyst=principal.name
        )
    except ToolError as error:
        raise _http_error(error) from error
    return {
        "iocs": [view.model_dump() for view in _ioc_views(outcome["iocs"])],
        "added": outcome["added"],
        "duplicates": outcome["duplicates"],
    }


@router.post("/cti/analyse", response_model=CtiAnalysisView)
async def analyze_cti_report(
    request: Request,
    filename: str = Query(default="report.pdf", max_length=200),
    principal: Principal = Depends(require_analyst),
) -> CtiAnalysisView:
    """Analyzes a CTI report (PDF, raw request body) and proposes hunts.

    The document comes from the analyst and does not leave the perimeter: its text goes to
    the model via the AI gateway, encapsulated as untrusted content. Nothing is created here:
    the proposals prefill the form, the analyst keeps control.
    """

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="No file received.")
    try:
        result = await _runtime(request).analyze_cti_report(
            data, filename=filename, actor=principal.name
        )
    except ToolError as error:
        raise _http_error(error) from error
    return CtiAnalysisView(**result)


@router.get("/cti/history", response_model=list[CtiHistoryEntry])
async def cti_history(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> list[CtiHistoryEntry]:
    entries = await _repository(request).cti_history()
    return [CtiHistoryEntry(**entry) for entry in entries]


@router.post("/cti/probe", response_model=CtiProbeView)
async def probe_cti_iocs(
    request: Request,
    payload: CtiProbeRequest,
    principal: Principal = Depends(require_analyst),
) -> CtiProbeView:
    """Checks whether threat intelligence publishes IOCs for a threat, without creating a hunt."""

    try:
        result = await _runtime(request).probe_iocs(
            payload.campaign_name,
            actor=principal.name,
            analysis_id=payload.analysis_id,
            attack_index=payload.attack_index,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return CtiProbeView(**result)


@router.get("/cti/analyses/{analysis_id}", response_model=CtiStoredAnalysisView)
async def get_cti_analysis(
    request: Request,
    analysis_id: str,
    principal: Principal = Depends(current_principal),
) -> CtiStoredAnalysisView:
    stored = await _repository(request).get_cti_analysis(analysis_id)
    if stored is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown analysis.")
    return CtiStoredAnalysisView(**stored)


@router.delete("/cti/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cti_analysis(
    request: Request,
    analysis_id: str,
    principal: Principal = Depends(require_analyst),
) -> None:
    """Deletes an analysis from history. The trace of its execution remains in the
    audit log, which itself cannot be modified."""

    removed = await _repository(request).delete_cti_analysis(analysis_id)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown analysis.")
    await _runtime(request).record_platform_event(
        AuditEventType.CTI_REPORT_DELETED,
        actor=principal.name,
        detail={"analysis_id": analysis_id},
    )


@router.post("/hunts/{hunt_id}/iocs/import")
async def import_iocs(
    request: Request,
    hunt_id: str,
    filename: str = Query(default="indicators.txt", max_length=200),
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Import of an indicator file (raw body: txt, csv, xlsx). The
    extracted indicators arrive awaiting validation."""

    data = await request.body()
    try:
        outcome = await _runtime(request).import_iocs(
            hunt_id, data=data, filename=filename, analyst=principal.name
        )
    except ToolError as error:
        raise _http_error(error) from error
    return {
        "iocs": [view.model_dump() for view in _ioc_views(outcome["iocs"])],
        "added": outcome["added"],
        "duplicates": outcome["duplicates"],
        "extracted": outcome["extracted"],
        "by_type": outcome["by_type"],
    }


@router.get("/hunts/{hunt_id}/iocs", response_model=list[IocView])
async def list_iocs(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
) -> list[IocView]:
    runtime = _runtime(request)
    if runtime.has(hunt_id):
        return _ioc_views(runtime.get(hunt_id).dossier.iocs)
    return _ioc_views(await _repository(request).load_iocs(hunt_id))


@router.post("/hunts/{hunt_id}/iocs/validate", response_model=list[IocView])
async def validate_iocs(
    request: Request,
    hunt_id: str,
    payload: ValidateIocsRequest,
    principal: Principal = Depends(require_analyst),
) -> list[IocView]:
    try:
        iocs = await _runtime(request).validate_iocs(
            hunt_id,
            validated=payload.validated,
            rejected=payload.rejected,
            analyst=principal.name,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return _ioc_views(iocs)


@router.post("/hunts/{hunt_id}/plan")
async def plan_hunt(
    request: Request,
    hunt_id: str,
    payload: PlanRequest | None = None,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Generates (or regenerates with an instruction) the playbook. Human checkpoint: nothing
    is launched until the analyst has validated the plan and its budgets."""

    try:
        playbook = await _runtime(request).plan(
            hunt_id,
            instruction=payload.instruction if payload else None,
            actor=principal.name,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return playbook.model_dump(mode="json")


@router.get("/hunts/{hunt_id}/plan")
async def get_plan(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
) -> dict[str, Any] | None:
    try:
        hunt = await _runtime(request).resolve(hunt_id)
    except ToolError as error:
        raise _http_error(error) from error
    playbook = hunt.dossier.playbook
    return playbook.model_dump(mode="json") if playbook else None


@router.post("/hunts/{hunt_id}/resume", status_code=status.HTTP_201_CREATED)
async def resume_hunt(
    request: Request,
    hunt_id: str,
    payload: ResumeHuntRequest | None = None,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Creates a new hunt that restarts from a finished or interrupted hunt: same
    validated indicators, context of the previous run, analyst's question. The original
    hunt is never modified; the checkpoints (playbook, budgets) apply."""

    try:
        hunt = await _runtime(request).resume(
            hunt_id,
            instruction=payload.instruction if payload else None,
            from_query_id=payload.from_query_id if payload else None,
            actor=principal.name,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return {
        "hunt_id": hunt.dossier.hunt_id,
        "status": hunt.dossier.status.value,
        "parent_hunt_id": hunt_id,
    }


@router.get("/hunts/{hunt_id}/resume-options")
async def resume_options(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    """What can be done with a stopped hunt: continue in place (saved loop
    state) or restart in a new linked investigation."""

    row = await _repository(request).get_hunt(hunt_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown hunt.")
    continuable = row["status"] == "interrupted" and await _runtime(request).continuable(hunt_id)
    return {"hunt_id": hunt_id, "status": row["status"], "continuable": continuable}


@router.post("/hunts/{hunt_id}/continue")
async def continue_hunt(
    request: Request,
    hunt_id: str,
    payload: StartHuntRequest | None = None,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Continues an interrupted hunt where its loop had stopped, budgets
    possibly raised by the analyst."""

    try:
        hunt = await _runtime(request).continue_hunt(
            hunt_id,
            actor=principal.name,
            max_iterations=payload.max_iterations if payload else None,
            max_siem_queries=payload.max_siem_queries if payload else None,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return {"hunt_id": hunt_id, "status": hunt.dossier.status.value, "running": hunt.running}


@router.post("/hunts/{hunt_id}/start")
async def start_hunt(
    request: Request,
    hunt_id: str,
    payload: StartHuntRequest | None = None,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        hunt = await _runtime(request).start(
            hunt_id,
            actor=principal.name,
            max_iterations=payload.max_iterations if payload else None,
            max_siem_queries=payload.max_siem_queries if payload else None,
        )
    except ToolError as error:
        raise _http_error(error) from error
    return {"hunt_id": hunt_id, "status": hunt.dossier.status.value, "running": hunt.running}


@router.post("/hunts/{hunt_id}/budget")
async def decide_budget(
    request: Request,
    hunt_id: str,
    payload: BudgetDecisionRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return await _runtime(request).decide_budget(
            hunt_id,
            extend=payload.action == "extend",
            extra_iterations=payload.extra_iterations,
            extra_siem_queries=payload.extra_siem_queries,
            extra_minutes=payload.extra_minutes,
            extra_tokens=payload.extra_tokens,
            actor=principal.name,
        )
    except ToolError as error:
        raise _http_error(error) from error


@router.post("/hunts/{hunt_id}/stop")
async def stop_hunt(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(require_analyst),
) -> dict[str, str]:
    try:
        await _runtime(request).stop(hunt_id)
    except ToolError as error:
        raise _http_error(error) from error
    return {"hunt_id": hunt_id, "status": "stop requested"}


@router.get("/hunts/{hunt_id}/events")
async def hunt_events(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
) -> StreamingResponse:
    """Live investigation feed, via Server-Sent Events, with history replay."""

    try:
        hunt = _runtime(request).get(hunt_id)
    except ToolError as error:
        raise _http_error(error) from error

    async def publish() -> Any:
        async for event in hunt.stream.subscribe():
            body = json.dumps(event.to_dict(), ensure_ascii=False, default=str)
            yield f"id: {event.sequence}\nevent: {event.type.value}\ndata: {body}\n\n"

    return StreamingResponse(
        publish(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/hunts/{hunt_id}/report")
async def get_report(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
    report_format: str = Query(default="json", alias="format", pattern="^(json|markdown|pdf)$"),
) -> Any:
    report = await _repository(request).load_report(hunt_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report unavailable.")
    if report_format == "markdown":
        return PlainTextResponse(to_markdown(report), media_type="text/markdown")
    if report_format == "pdf":
        return Response(
            content=to_pdf(report, organisation=_runtime(request).settings.report_organisation),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{hunt_id}.pdf"'},
        )
    return report.model_dump(mode="json")


@router.post("/hunts/{hunt_id}/decision")
async def record_decision(
    request: Request,
    hunt_id: str,
    payload: DecisionRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Second human checkpoint: the agent's verdict becomes a dated and attributed decision."""

    repository = _repository(request)
    recorded = await repository.record_decision(
        hunt_id,
        verdict=payload.verdict,
        decided_by=principal.name,
        comment=payload.comment,
    )
    if not recorded:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report unavailable.")

    runtime = _runtime(request)
    if runtime.has(hunt_id):
        hunt = runtime.get(hunt_id)
        hunt.dossier.status = HuntStatus.CLOSED
        await hunt.journal.record(
            AuditEventType.REPORT_VALIDATED,
            actor=principal.name,
            detail={"verdict": payload.verdict.value, "comment": payload.comment},
        )
    return {
        "hunt_id": hunt_id,
        "verdict": Verdict(payload.verdict).value,
        "decided_by": principal.name,
    }


@router.delete("/hunts/{hunt_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hunt(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(require_analyst),
) -> None:
    """Deletes a hunt from history. The audit log is preserved."""

    try:
        removed = await _runtime(request).delete(hunt_id, actor=principal.name)
    except ToolError as error:
        raise _http_error(error) from error
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown hunt.")


@router.get("/hunts/{hunt_id}/audit")
async def audit_trail(
    request: Request,
    hunt_id: str,
    principal: Principal = Depends(current_principal),
) -> list[dict[str, Any]]:
    return await _repository(request).audit_trail(hunt_id)


@router.get("/dashboard")
async def dashboard(
    request: Request,
    principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    return await _repository(request).dashboard()

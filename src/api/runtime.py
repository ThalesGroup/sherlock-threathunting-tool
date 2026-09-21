"""Assembly and lifecycle of hunts.

This is where the layers are wired together: one hunt = one dossier, one budget, one journal,
one executor and one event stream. Nothing is shared between two hunts, which guarantees that a
budget or a set of validated indicators does not leak from one investigation to another.

A source whose credentials are not configured stays absent rather than failing at call time:
the model learns that it does not exist and adapts its plan.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from api.schemas import (
    CreateHuntRequest,
    SecretFieldView,
    SourceConfigView,
    SourceTestResult,
)
from middleware.anonymizer import SemanticAnonymizer
from middleware.audit import AuditEventType, AuditJournal, AuditSink
from middleware.budgets import HuntBudget
from middleware.clients.defender import DefenderClient
from middleware.clients.entra import EntraCredentials, EntraTokenProvider
from middleware.clients.gcp import GcpCredentials, GcpTokenProvider
from middleware.clients.secops import SCOPE as SECOPS_SCOPE
from middleware.clients.secops import SecOpsClient, resolve_instance
from middleware.clients.sentinel import SentinelClient, resolve_workspace_id
from middleware.clients.simulated import SimulatedSiemClient
from middleware.clients.ti import (
    MispFeedSource,
    OtxSource,
    ThreatFoxSource,
    ThreatIntelConnector,
    ThreatIntelSource,
    VirusTotalSource,
)
from middleware.clients.ti_web import WebReportSource
from middleware.config import Budgets, Settings
from middleware.cti import analyze_report_text, extract_pdf_text
from middleware.errors import ErrorCode, ToolError
from middleware.executor import QueryLedger, SiemExecutor, record_from_payload, record_to_payload
from middleware.guardrails.ioc import Ioc, IocStatus, ManualIoc
from middleware.ioc_import import extract_indicators, extract_text
from middleware.secrets import ConfigurableSecretProvider, SecretProvider
from middleware.tokenization import TokenVault
from orchestrator.events import EventStream
from orchestrator.gateway import GatewayClient
from orchestrator.knowledge import load_knowledge
from orchestrator.loop import HuntOrchestrator, HuntOutcome
from orchestrator.planning import PLATFORM_CAP, propose_playbook
from reporting.dossier import Dossier
from reporting.models import Finding, HuntReport, HuntStatus, Playbook
from storage.repository import HuntRepository
from tools.definitions import ToolRegistry, build_enrichment_registry, build_registry


@dataclass(frozen=True)
class SourceDefinition:
    """Entry in the Configuration screen catalog. Closed list: the API only accepts
    writing the keys named here, it cannot become a generic store."""

    id: str
    label: str
    kind: str
    secret_names: tuple[str, ...]


SOURCE_DEFINITIONS: tuple[SourceDefinition, ...] = (
    SourceDefinition(
        "gateway", "the AI gateway (reasoning engine)", "engine", ("GATEWAY_API_KEY",)
    ),
    SourceDefinition(
        "anonymizer",
        "Anonymization engine (local model)",
        "engine",
        ("ANONYMIZER_API_KEY",),
    ),
    SourceDefinition(
        "entra",
        "Microsoft Sentinel & Defender (app registration Entra ID)",
        "siem",
        (
            "ENTRA_TENANT_ID",
            "ENTRA_CLIENT_ID",
            "ENTRA_CLIENT_SECRET",
            "SENTINEL_SUBSCRIPTION_ID",
            "SENTINEL_RESOURCE_GROUP",
            "SENTINEL_WORKSPACE_NAME",
            "SENTINEL_WORKSPACE_ID",
        ),
    ),
    SourceDefinition(
        "secops",
        "Google SecOps (Chronicle service account)",
        "siem",
        ("SECOPS_SA_KEY", "SECOPS_INSTANCE_PATH"),
    ),
    SourceDefinition("virustotal", "VirusTotal", "ti", ("VIRUSTOTAL_API_KEY",)),
    SourceDefinition("otx", "AlienVault OTX", "ti", ("OTX_API_KEY",)),
    SourceDefinition("threatfox", "ThreatFox (abuse.ch)", "ti", ("THREATFOX_API_KEY",)),
    SourceDefinition("circl", "CIRCL OSINT (MISP)", "ti", ()),
    SourceDefinition(
        "publisher-reports",
        "Vendor reports (web search)",
        "ti",
        ("TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY", "SEARCH_API_KEY", "SEARCH_ENGINE_ID"),
    ),
)

CONFIGURABLE_SECRETS = frozenset(
    name for definition in SOURCE_DEFINITIONS for name in definition.secret_names
)

_ENTRA_IDENTITY_FIELDS = ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET")
_WORKSPACE_FIELDS = (
    "SENTINEL_SUBSCRIPTION_ID",
    "SENTINEL_RESOURCE_GROUP",
    "SENTINEL_WORKSPACE_NAME",
)
_DIRECT_WORKSPACE_ID = "SENTINEL_WORKSPACE_ID"
"""Workspace ID entered directly (the "Workspace ID" GUID from the workspace overview).
Takes precedence over resolution by name."""
_RESOLVED_WORKSPACE_ID = "SENTINEL_WORKSPACE_ID_RESOLVED"
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
"""Workspace ID resolved by the platform from the SENTINEL_* fields. Written by the
runtime only: absent from the catalog, the API cannot set it directly."""
_DEFAULT_WORKSPACE_ALIAS = "soc-principal"


def effective_workspace_aliases(
    env_aliases: dict[str, str], resolved_id: str | None
) -> dict[str, str]:
    """The server aliases (SHL_WORKSPACE_ALIASES) take precedence; otherwise, the workspace
    resolved from the Configuration screen carries the default alias."""

    if env_aliases:
        return dict(env_aliases)
    if resolved_id:
        return {_DEFAULT_WORKSPACE_ALIAS: resolved_id}
    return {}


_PLATFORM_AUDIT_ID = "platform"


@dataclass
class SiemClients:
    sentinel: SentinelClient | None = None
    defender: DefenderClient | None = None
    secops: SecOpsClient | None = None

    def available(self) -> list[str]:
        names = []
        if self.sentinel:
            names.append("sentinel")
        if self.defender:
            names.append("defender")
        if self.secops:
            names.append("secops")
        return names


@dataclass
class ActiveHunt:
    dossier: Dossier
    journal: AuditJournal
    budget: HuntBudget
    executor: SiemExecutor
    registry: ToolRegistry
    enrichment: ToolRegistry
    stream: EventStream
    orchestrator: HuntOrchestrator
    task: asyncio.Task[HuntOutcome] | None = None
    sources: list[str] = field(default_factory=list)
    window: tuple[datetime, datetime] | None = None
    vault: TokenVault | None = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()


def _explain_gateway_refusal(
    error: ToolError, *, endpoint: str, model: str, url_setting: str, model_setting: str
) -> ToolError:
    """A bare 401/4xx says nothing about what to look at. A key issued for another offer
    often changes the endpoint and the model too: the error names all three."""

    if error.code is ErrorCode.UPSTREAM_REJECTED:
        return ToolError(
            ErrorCode.UPSTREAM_REJECTED,
            f"Call refused by {endpoint} (model {model}).",
            hint=(
                "Key refused or unknown to this endpoint. Check that the key saved here is "
                "the latest one (the store takes precedence over .env), and if it comes from "
                f"another offer, the server-side endpoint and model: {url_setting}, "
                f"{model_setting} (restart required)."
            ),
        )
    if error.code is ErrorCode.UPSTREAM_UNAVAILABLE:
        return ToolError(
            ErrorCode.UPSTREAM_UNAVAILABLE,
            f"{endpoint} unreachable.",
            hint=(
                "Network, DNS or TLS from this server (the client connects directly, without "
                f"proxy). Check {url_setting} and the firewall flow to that host."
            ),
        )
    return error


class HuntRuntime:
    def __init__(
        self,
        *,
        settings: Settings,
        repository: HuntRepository,
        audit_sink: AuditSink,
        gateway: GatewayClient,
        clients: SiemClients,
        threat_intel: ThreatIntelConnector | None = None,
        secrets: ConfigurableSecretProvider | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._audit_sink = audit_sink
        self._gateway = gateway
        self._clients = clients
        self._threat_intel = threat_intel
        self._secrets = secrets
        self._env_workspace_aliases = dict(settings.workspace_aliases)
        if self._apply_workspace_aliases() and secrets is not None:
            self._clients = build_clients(settings, secrets)
        self._knowledge = load_knowledge(settings.knowledge_dir)
        self._hunts: dict[str, ActiveHunt] = {}
        self._anonymizer_client = self._build_anonymizer_client()
        self._probe_cache: dict[str, tuple[float, list[Ioc]]] = {}
        """Recent CTI probe results, by threat name. Used to carry the IOCs already found
        (with their real sources) into a hunt created right after the probe, without going
        back through the browser - a client cannot fabricate a source."""

    def _apply_workspace_aliases(self) -> bool:
        """Recomputes the workspace aliases from the server and the store. Returns true
        if the result differs from the current configuration."""

        stored = None
        if self._secrets is not None:
            stored = self._secrets.get_optional(_DIRECT_WORKSPACE_ID) or self._secrets.get_optional(
                _RESOLVED_WORKSPACE_ID
            )
        aliases = effective_workspace_aliases(self._env_workspace_aliases, stored)
        changed = aliases != self._settings.workspace_aliases
        self._settings.workspace_aliases = aliases
        return changed

    async def resolve_workspace(self, *, actor: str) -> str | None:
        """Resolves the Workspace ID from the SENTINEL_* fields (subscription, resource
        group, name) via Azure Resource Manager and stores it. If the fields are
        incomplete, the stored identifier is removed."""

        secrets = self._require_secrets()
        direct = secrets.get_optional(_DIRECT_WORKSPACE_ID)
        if direct:
            return direct
        values = {name: secrets.get_optional(name) for name in _WORKSPACE_FIELDS}
        if not all(values.values()):
            if secrets.delete(_RESOLVED_WORKSPACE_ID):
                await self._audit_config(
                    AuditEventType.CONFIG_SECRET_DELETED,
                    actor=actor,
                    detail={"secret": _RESOLVED_WORKSPACE_ID, "reason": "incomplete fields"},
                )
            return None
        provider = self._entra_provider(secrets)
        try:
            workspace_id = await resolve_workspace_id(
                provider,
                subscription_id=values["SENTINEL_SUBSCRIPTION_ID"] or "",
                resource_group=values["SENTINEL_RESOURCE_GROUP"] or "",
                workspace_name=values["SENTINEL_WORKSPACE_NAME"] or "",
            )
        finally:
            await provider.aclose()
        secrets.set(_RESOLVED_WORKSPACE_ID, workspace_id, actor=actor)
        await self._audit_config(
            AuditEventType.CONFIG_SECRET_UPDATED,
            actor=actor,
            detail={"secret": _RESOLVED_WORKSPACE_ID, "resolved_from": "SENTINEL_WORKSPACE_NAME"},
        )
        return workspace_id

    def _build_anonymizer_client(self) -> GatewayClient | None:
        """Client to the anonymization endpoint (semantic pass). Absent if the anonymizer
        is not configured: the deterministic layer stays active on its own."""

        settings = self._settings
        if not settings.semantic_anonymization or self._secrets is None:
            return None
        base = settings.anonymizer_base_url or settings.gateway_base_url
        key = self._secrets.get_optional("ANONYMIZER_API_KEY")
        if not (base and key):
            return None
        return GatewayClient(base_url=base, api_key=key, trust_proxy_env=False)

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def threat_intel_enabled(self) -> bool:
        return self._threat_intel is not None and self._threat_intel.enabled

    @property
    def available_sources(self) -> list[str]:
        return self._clients.available()

    def get(self, hunt_id: str) -> ActiveHunt:
        hunt = self._hunts.get(hunt_id)
        if hunt is None:
            raise ToolError(ErrorCode.UNKNOWN_TARGET, "Unknown or already archived hunt.")
        return hunt

    def has(self, hunt_id: str) -> bool:
        return hunt_id in self._hunts

    async def create(self, request: CreateHuntRequest, *, analyst: str) -> ActiveHunt:
        hunt_id = f"hunt_{uuid.uuid4().hex[:12]}"
        hypothesis = request.hypothesis or (
            f"Investigation into the campaign or actor {request.campaign}."
        )
        iocs = [
            ManualIoc(
                value=item.value,
                type=item.type,
                provided_by=analyst,
                note=item.note,
                validated_at=datetime.now(UTC).isoformat(),
            ).to_ioc()
            for item in request.manual_iocs
        ]
        seeded = 0
        if request.campaign:
            known = {ioc.normalized() for ioc in iocs}
            for ioc in self._cached_probe_iocs(request.campaign):
                if ioc.normalized() not in known:
                    iocs.append(ioc)
                    known.add(ioc.normalized())
                    seeded += 1
        status = (
            HuntStatus.AWAITING_IOC_VALIDATION
            if (request.campaign and not iocs)
            or any(ioc.status is IocStatus.PENDING_VALIDATION for ioc in iocs)
            else HuntStatus.DRAFT
        )
        """The IOC checkpoint only applies if there will be indicators to validate: a
        campaign calls for enrichment, manual IOCs arrive already validated, and a
        pure-hypothesis hunt has nothing to submit to the checkpoint - it is launchable as
        is, the guardrail on the indicators of queries remaining active in every case."""

        window: tuple[datetime, datetime] | None = None
        if request.window_start:
            window_start = datetime.fromisoformat(request.window_start.replace("Z", "+00:00"))
            window_end = (
                datetime.fromisoformat(request.window_end.replace("Z", "+00:00"))
                if request.window_end
                else datetime.now(UTC)
            )
            window = (window_start, window_end)

        hunt = self._assemble(
            hunt_id=hunt_id,
            hypothesis=hypothesis,
            campaign=request.campaign,
            analyst=analyst,
            iocs=iocs,
            status=status,
            limits=self._budgets_for(request),
            sources=self._selected_sources(request),
            window=window,
        )
        self._hunts[hunt_id] = hunt

        await self._repository.create_hunt(hunt.dossier)
        await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
        await hunt.journal.record(
            AuditEventType.HUNT_CREATED,
            detail={
                "hypothesis": hypothesis,
                "campaign": request.campaign,
                "manual_iocs": len(request.manual_iocs),
                "seeded_from_probe": seeded,
                "sources": hunt.sources,
                "window": (
                    f"{window[0].isoformat()} -> {window[1].isoformat()}" if window else None
                ),
            },
        )
        return hunt

    def _cached_probe_iocs(self, campaign: str) -> list[Ioc]:
        """IOCs from a recent probe (15 min) for this threat, copied for the hunt."""

        entry = self._probe_cache.get(campaign.strip().lower())
        if entry is None or time.monotonic() - entry[0] > 900:
            return []
        return [ioc.model_copy(deep=True) for ioc in entry[1]]

    async def resolve(self, hunt_id: str) -> ActiveHunt:
        """Active hunt, restored from the database if it was lost by a restart.

        Only the upstream phase is restorable (draft, indicators to validate): a hunt whose
        loop was in flight cannot resume, it stays unknown. The custom budgets and
        investigation period are not persisted: a restored hunt starts over on the default
        values."""

        active = self._hunts.get(hunt_id)
        if active is not None:
            return active
        row = await self._repository.get_hunt(hunt_id)
        if row is None or row["status"] not in (
            HuntStatus.DRAFT.value,
            HuntStatus.AWAITING_IOC_VALIDATION.value,
            HuntStatus.AWAITING_PLAN_VALIDATION.value,
        ):
            raise ToolError(ErrorCode.UNKNOWN_TARGET, "Unknown or already archived hunt.")
        iocs = await self._repository.load_iocs(hunt_id)
        hunt = self._assemble(
            hunt_id=hunt_id,
            hypothesis=row["hypothesis"],
            campaign=row.get("campaign"),
            analyst=row["analyst"],
            iocs=iocs,
            status=HuntStatus(row["status"]),
            limits=self._settings.budgets,
            sources=self._clients.available(),
            window=None,
        )
        if row.get("playbook"):
            hunt.dossier.playbook = Playbook.model_validate(row["playbook"])
        hunt.dossier.parent_hunt_id = row.get("parent_hunt_id")
        hunt.dossier.resume_context = row.get("resume_context")
        self._hunts[hunt_id] = hunt
        return hunt

    def _assemble(
        self,
        *,
        hunt_id: str,
        hypothesis: str,
        campaign: str | None,
        analyst: str,
        iocs: list[Ioc],
        status: HuntStatus,
        limits: Budgets,
        sources: list[str],
        window: tuple[datetime, datetime] | None,
        vault: TokenVault | None = None,
    ) -> ActiveHunt:
        journal = AuditJournal(self._audit_sink, hunt_id=hunt_id, actor=analyst)
        budget = HuntBudget(limits=limits)
        ledger = QueryLedger()

        dossier = Dossier(
            hunt_id=hunt_id,
            hypothesis=hypothesis,
            analyst=analyst,
            campaign=campaign,
            ledger=ledger,
        )
        dossier.iocs = iocs
        dossier.status = status

        if vault is None:
            vault = (
                TokenVault(internal_suffixes=self._settings.internal_hostname_suffixes)
                if self._settings.tokenization.enabled
                else None
            )
        anonymizer = (
            SemanticAnonymizer(
                client=self._anonymizer_client,
                model=self._settings.anonymizer_model,
                vault=vault,
                fail_closed=self._settings.semantic_anonymization_fail_closed,
            )
            if self._anonymizer_client is not None and vault is not None
            else None
        )
        executor = SiemExecutor(
            settings=self._settings,
            journal=journal,
            budget=budget,
            ledger=ledger,
            sentinel=self._clients.sentinel,
            defender=self._clients.defender,
            secops=self._clients.secops,
            vault=vault,
            anonymizer=anonymizer,
            window=window,
        )
        executor.set_iocs(dossier.iocs)

        registry = build_registry(
            executor=executor,
            dossier=dossier,
            journal=journal,
            vault=vault,
            workspaces=tuple(sorted(self._settings.workspace_aliases)),
        )
        enrichment = build_enrichment_registry(
            dossier=dossier,
            journal=journal,
            threat_intel=self._threat_intel,
        )
        stream = EventStream(hunt_id)

        orchestrator = HuntOrchestrator(
            dossier=dossier,
            registry=registry,
            journal=journal,
            budget=budget,
            stream=stream,
            gateway=self._gateway,
            model=self._settings.gateway_model_query,
            analysis_model=self._settings.gateway_model_analysis,
            available_sources=sources,
            knowledge=self._knowledge,
            vault=vault,
            investigation_window=(
                f"{window[0].isoformat()} -> {window[1].isoformat()}" if window else None
            ),
            budget_pause_timeout=float(self._settings.budget_pause_timeout_seconds),
            workspaces=sorted(self._settings.workspace_aliases),
        )

        return ActiveHunt(
            dossier=dossier,
            journal=journal,
            budget=budget,
            executor=executor,
            registry=registry,
            enrichment=enrichment,
            stream=stream,
            orchestrator=orchestrator,
            sources=sources,
            window=window,
            vault=vault,
        )

    async def enrich(
        self,
        hunt_id: str,
        *,
        campaign_name: str,
        ioc_types: list[Any] | None,
        max_results: int,
        time_range: str | None = None,
    ) -> list[Ioc]:
        hunt = await self.resolve(hunt_id)
        self._refuse_if_running(hunt)
        if hunt.dossier.status not in (
            HuntStatus.DRAFT,
            HuntStatus.AWAITING_IOC_VALIDATION,
        ):
            raise ToolError(
                ErrorCode.EGRESS_BLOCKED,
                "Enrichment is only possible before the hunt is launched.",
                hint=(
                    "The only outbound flow of the platform is confined to the upstream "
                    "phase, before the validation of the indicators."
                ),
            )
        epoch = hunt.dossier.ioc_epoch
        result = await hunt.enrichment.dispatch(
            "get_iocs_for_campaign",
            {
                "campaign_name": campaign_name,
                "ioc_types": [item.value for item in ioc_types] if ioc_types else None,
                "max_results": max_results,
                "time_range": time_range,
            },
        )
        if "error" in result:
            raise ToolError(ErrorCode(result["error"]), result.get("message", "Search refused."))

        if hunt.dossier.ioc_epoch != epoch:
            stale = [ioc for ioc in hunt.dossier.iocs if ioc.status is IocStatus.PENDING_VALIDATION]
            hunt.dossier.iocs = [
                ioc for ioc in hunt.dossier.iocs if ioc.status is not IocStatus.PENDING_VALIDATION
            ]
            hunt.executor.set_iocs(hunt.dossier.iocs)
            await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
            await hunt.journal.record(
                AuditEventType.IOC_SEARCH,
                detail={
                    "campaign": campaign_name,
                    "stale_discarded": len(stale),
                    "reason": "indicators validated during the search: late results "
                    "discarded, the checkpoint remains cleared",
                },
            )
            return hunt.dossier.iocs

        hunt.dossier.status = HuntStatus.AWAITING_IOC_VALIDATION
        hunt.executor.set_iocs(hunt.dossier.iocs)
        await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
        await self._repository.set_status(hunt_id, hunt.dossier.status)
        return hunt.dossier.iocs

    async def import_iocs(
        self, hunt_id: str, *, data: bytes, filename: str, analyst: str
    ) -> dict[str, Any]:
        """Import of an indicators file (txt, csv, xlsx). Pattern-based extraction,
        deduplication against the hunt list; the imported indicators arrive pending
        validation - the import replaces the manual entry, not the checkpoint."""

        hunt = await self.resolve(hunt_id)
        self._refuse_if_running(hunt)
        if hunt.dossier.status not in (
            HuntStatus.DRAFT,
            HuntStatus.AWAITING_IOC_VALIDATION,
        ):
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "Importing indicators is only possible before the hunt is launched.",
            )
        text = extract_text(data, filename)
        extracted = extract_indicators(text)
        existing = {ioc.normalized() for ioc in hunt.dossier.iocs}
        added: list[str] = []
        duplicates: list[str] = []
        by_type: dict[str, int] = {}
        for value, ioc_type in extracted:
            ioc = Ioc(
                value=value,
                type=ioc_type,
                source_name=f"import {filename} (analyst:{analyst})",
                source_url=f"internal://analyst/{analyst}",
                confidence="analyst",
                status=IocStatus.PENDING_VALIDATION,
            )
            if ioc.normalized() in existing:
                duplicates.append(value)
                continue
            existing.add(ioc.normalized())
            hunt.dossier.iocs.append(ioc)
            added.append(value)
            by_type[ioc_type.value] = by_type.get(ioc_type.value, 0) + 1

        if added:
            hunt.dossier.status = HuntStatus.AWAITING_IOC_VALIDATION
            await self._repository.set_status(hunt_id, hunt.dossier.status)
        hunt.executor.set_iocs(hunt.dossier.iocs)
        await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
        await hunt.journal.record(
            AuditEventType.IOC_IMPORT,
            actor=analyst,
            detail={
                "filename": filename,
                "extracted": len(extracted),
                "added": len(added),
                "duplicates": len(duplicates),
                "by_type": by_type,
            },
        )
        return {
            "iocs": hunt.dossier.iocs,
            "added": len(added),
            "duplicates": len(duplicates),
            "extracted": len(extracted),
            "by_type": by_type,
        }

    async def add_manual_iocs(self, hunt_id: str, *, items: list[Any], analyst: str) -> list[Ioc]:
        """Indicators added by the analyst on the validation screen. They complement those
        from threat intelligence, with the analyst as source, and arrive validated:
        providing them is already an act of validation."""

        hunt = await self.resolve(hunt_id)
        self._refuse_if_running(hunt)
        if hunt.dossier.status not in (
            HuntStatus.DRAFT,
            HuntStatus.AWAITING_IOC_VALIDATION,
        ):
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "Adding indicators is only possible before the hunt is launched.",
            )

        existing = {ioc.normalized() for ioc in hunt.dossier.iocs}
        stamped = datetime.now(UTC).isoformat()
        added = 0
        duplicates: list[str] = []
        for item in items:
            ioc = ManualIoc(
                value=item.value,
                type=item.type,
                provided_by=analyst,
                note=item.note,
                validated_at=stamped,
            ).to_ioc()
            if ioc.normalized() in existing:
                duplicates.append(item.value)
                continue
            existing.add(ioc.normalized())
            hunt.dossier.iocs.append(ioc)
            added += 1

        hunt.executor.set_iocs(hunt.dossier.iocs)
        await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
        await hunt.journal.record(
            AuditEventType.IOC_VALIDATION,
            detail={
                "action": "manual_add",
                "added": added,
                "submitted": len(items),
                "duplicates": duplicates,
            },
        )
        return {
            "iocs": hunt.dossier.iocs,
            "added": added,
            "duplicates": duplicates,
        }

    async def validate_iocs(
        self,
        hunt_id: str,
        *,
        validated: list[str],
        rejected: list[str],
        analyst: str,
    ) -> list[Ioc]:
        """First human checkpoint. Until it is cleared, no SIEM is reachable."""

        hunt = await self.resolve(hunt_id)
        self._refuse_if_running(hunt)
        keep = {value.strip().lower() for value in validated}
        drop = {value.strip().lower() for value in rejected}
        stamped = datetime.now(UTC).isoformat()

        hunt.dossier.ioc_epoch += 1
        for ioc in hunt.dossier.iocs:
            key = ioc.value.strip().lower()
            if key in keep:
                ioc.status = IocStatus.VALIDATED
                ioc.validated_by = analyst
                ioc.validated_at = stamped
            elif key in drop or ioc.status is IocStatus.PENDING_VALIDATION:
                ioc.status = IocStatus.REJECTED
                ioc.validated_by = analyst
                ioc.validated_at = stamped

        hunt.executor.set_iocs(hunt.dossier.iocs)
        hunt.dossier.status = HuntStatus.DRAFT

        await self._repository.replace_iocs(hunt_id, hunt.dossier.iocs)
        await self._repository.set_status(hunt_id, hunt.dossier.status)
        await hunt.journal.record(
            AuditEventType.IOC_VALIDATION,
            actor=analyst,
            detail={
                "validated": sorted(keep),
                "rejected": sorted(drop),
                "total": len(hunt.dossier.iocs),
            },
        )
        return hunt.dossier.iocs

    async def resume(
        self,
        hunt_id: str,
        *,
        instruction: str | None,
        from_query_id: str | None,
        actor: str,
    ) -> ActiveHunt:
        """New hunt that starts over from a completed or interrupted hunt. The parent is
        never modified; the context passed on is rebuilt from what is persisted (report,
        or the audit journal if none), truncated to the chosen query where applicable. The
        parent's validated IOCs stay validated: the IOC checkpoint is acquired, those of
        the playbook and the report apply normally."""

        row = await self._repository.get_hunt(hunt_id)
        if row is None:
            raise ToolError(ErrorCode.UNKNOWN_TARGET, "Unknown hunt.")
        if row["status"] not in (
            HuntStatus.INTERRUPTED.value,
            HuntStatus.AWAITING_REVIEW.value,
            HuntStatus.CLOSED.value,
        ):
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "Only a completed or interrupted hunt can be resumed.",
                hint="A hunt in the upstream phase continues directly, without resumption.",
            )
        report = await self._repository.load_report(hunt_id)
        audit = await self._repository.audit_trail(hunt_id)
        context = build_resume_context(
            parent_id=hunt_id,
            row=row,
            report=report,
            audit=audit,
            from_query_id=from_query_id,
            instruction=instruction,
        )
        iocs = [
            ioc.model_copy(deep=True)
            for ioc in await self._repository.load_iocs(hunt_id)
            if ioc.status is IocStatus.VALIDATED
        ]
        window: tuple[datetime, datetime] | None = None
        if report is not None and report.investigation_window:
            ends = [part.strip() for part in report.investigation_window.split("->")]
            if len(ends) == 2:
                try:
                    window = (datetime.fromisoformat(ends[0]), datetime.fromisoformat(ends[1]))
                except ValueError:
                    window = None

        new_id = f"hunt_{uuid.uuid4().hex[:12]}"
        hunt = self._assemble(
            hunt_id=new_id,
            hypothesis=row["hypothesis"],
            campaign=row.get("campaign"),
            analyst=actor,
            iocs=iocs,
            status=HuntStatus.DRAFT,
            limits=self._settings.budgets,
            sources=self._clients.available(),
            window=window,
        )
        hunt.dossier.parent_hunt_id = hunt_id
        hunt.dossier.resume_context = context
        self._hunts[new_id] = hunt

        await self._repository.create_hunt(hunt.dossier)
        await self._repository.replace_iocs(new_id, hunt.dossier.iocs)
        await hunt.journal.record(
            AuditEventType.HUNT_CREATED,
            detail={
                "hypothesis": row["hypothesis"],
                "campaign": row.get("campaign"),
                "resumed_from": hunt_id,
                "from_query_id": from_query_id,
                "instruction": instruction,
                "inherited_iocs": len(iocs),
                "sources": hunt.sources,
            },
        )
        parent_journal = AuditJournal(self._audit_sink, hunt_id=hunt_id, actor=actor)
        await parent_journal.record(
            AuditEventType.HUNT_RESUMED,
            detail={
                "child": new_id,
                "from_query_id": from_query_id,
                "instruction": instruction,
            },
        )
        return hunt

    async def plan(self, hunt_id: str, *, instruction: str | None, actor: str) -> Playbook:
        """Generates the hunt playbook: plan of leads and query estimate, submitted to the
        analyst. Regeneratable with an instruction as long as the hunt is not launched."""

        hunt = await self.resolve(hunt_id)
        self._refuse_if_running(hunt)
        if hunt.dossier.status is HuntStatus.AWAITING_IOC_VALIDATION or any(
            ioc.status is IocStatus.PENDING_VALIDATION for ioc in hunt.dossier.iocs
        ):
            raise ToolError(
                ErrorCode.IOC_NOT_VALIDATED,
                "Some indicators are awaiting the analyst's validation: the plan is "
                "built on the selected indicators.",
            )
        if self._gateway is None:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "AI gateway not configured: planning impossible.",
            )
        playbook = await propose_playbook(
            self._gateway,
            model=self._settings.gateway_model_analysis or self._settings.gateway_model_query,
            briefing=hunt.orchestrator.briefing(),
            available_sources=hunt.sources,
            instruction=instruction,
        )
        hunt.dossier.playbook = playbook
        hunt.dossier.status = HuntStatus.AWAITING_PLAN_VALIDATION
        await self._repository.set_playbook(hunt_id, playbook.model_dump(mode="json"))
        await self._repository.set_status(hunt_id, HuntStatus.AWAITING_PLAN_VALIDATION)
        await hunt.journal.record(
            AuditEventType.PLAN_PROPOSED,
            detail={
                "steps": len(playbook.steps),
                "estimated_queries": playbook.estimated_queries,
                "estimated_iterations": playbook.estimated_iterations,
                "instruction": playbook.instruction,
                "requested_by": actor,
            },
        )
        return playbook

    async def start(
        self,
        hunt_id: str,
        *,
        actor: str = "",
        max_iterations: int | None = None,
        max_siem_queries: int | None = None,
    ) -> ActiveHunt:
        """Launches the loop. The budgets come from the validated playbook, possibly
        adjusted by the analyst; without a playbook, the analyst must set them explicitly -
        there is no launch without a human decision on what the hunt can spend."""

        hunt = await self.resolve(hunt_id)
        if hunt.running:
            return hunt
        pending = sum(1 for ioc in hunt.dossier.iocs if ioc.status is IocStatus.PENDING_VALIDATION)
        if pending:
            raise ToolError(
                ErrorCode.IOC_NOT_VALIDATED,
                f"{pending} indicator(s) awaiting the analyst's validation.",
                hint=(
                    "Return to the \"Indicators\" screen to validate or reject them, "
                    "then relaunch."
                ),
            )
        playbook = hunt.dossier.playbook
        if playbook is None and (max_iterations is None or max_siem_queries is None):
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "The playbook has not been validated.",
                hint=(
                    "Generate the playbook and validate its budgets, or explicitly set "
                    "the iterations and SIEM queries at launch."
                ),
            )
        iterations = min(
            max_iterations or (playbook.estimated_iterations if playbook else 0), PLATFORM_CAP
        )
        queries = min(
            max_siem_queries or (playbook.estimated_queries if playbook else 0), PLATFORM_CAP
        )
        current = hunt.budget.limits
        hunt.budget.limits = Budgets(
            max_iterations=iterations,
            max_siem_queries=queries,
            max_tokens=current.max_tokens,
            max_duration_seconds=current.max_duration_seconds,
            token_alert_ratio=current.token_alert_ratio,
            cache_read_cost_ratio=current.cache_read_cost_ratio,
            cache_write_cost_ratio=current.cache_write_cost_ratio,
        )
        now = datetime.now(UTC).isoformat()
        if playbook is not None:
            playbook.validated_by = actor or hunt.dossier.analyst
            playbook.validated_at = now
            playbook.validated_queries = queries
            playbook.validated_iterations = iterations
            await self._repository.set_playbook(hunt_id, playbook.model_dump(mode="json"))
        await hunt.journal.record(
            AuditEventType.PLAN_VALIDATED,
            detail={
                "by": actor or hunt.dossier.analyst,
                "max_iterations": iterations,
                "max_siem_queries": queries,
                "from_playbook": playbook is not None,
                "adjusted": bool(
                    playbook is not None
                    and (
                        iterations != playbook.estimated_iterations
                        or queries != playbook.estimated_queries
                    )
                ),
            },
        )
        hunt.dossier.status = HuntStatus.RUNNING
        await self._repository.set_status(hunt_id, HuntStatus.RUNNING)
        hunt.orchestrator.set_state_saver(self._state_saver_for(hunt))
        hunt.task = asyncio.create_task(self._run(hunt))
        return hunt

    def _state_saver_for(self, hunt: ActiveHunt) -> Any:
        """Hunt resumption state, saved after each iteration: tokenized transcript,
        pseudonym table, consumed budgets, query ledger, findings. Purged at conclusion;
        this is what lets "Continue this hunt" restart in the middle of the loop after an
        interruption."""

        async def save(messages: list[dict[str, Any]]) -> None:
            budget = hunt.budget
            payload = {
                "messages": messages,
                "vault": hunt.vault.snapshot() if hunt.vault else None,
                "budget": {
                    "iterations": budget.iterations,
                    "siem_queries": budget.siem_queries,
                    "tokens": budget.tokens,
                    "elapsed_seconds": budget.elapsed_seconds,
                    "max_iterations": budget.limits.max_iterations,
                    "max_siem_queries": budget.limits.max_siem_queries,
                },
                "records": [record_to_payload(record) for record in hunt.dossier.ledger.as_list()],
                "findings": [finding.model_dump(mode="json") for finding in hunt.dossier.findings],
                "window": (
                    [hunt.window[0].isoformat(), hunt.window[1].isoformat()]
                    if hunt.window
                    else None
                ),
                "saved_at": datetime.now(UTC).isoformat(),
            }
            await self._repository.save_hunt_state(hunt.dossier.hunt_id, payload)

        return save

    async def continuable(self, hunt_id: str) -> bool:
        return await self._repository.load_hunt_state(hunt_id) is not None

    async def continue_hunt(
        self,
        hunt_id: str,
        *,
        actor: str,
        max_iterations: int | None = None,
        max_siem_queries: int | None = None,
    ) -> ActiveHunt:
        """Continues an interrupted hunt where its loop had stopped: transcript,
        pseudonyms, consumed budgets, queries and findings are reloaded from the saved
        state. The analyst can raise the caps in the process."""

        active = self._hunts.get(hunt_id)
        if active is not None and active.running:
            return active
        row = await self._repository.get_hunt(hunt_id)
        if row is None:
            raise ToolError(ErrorCode.UNKNOWN_TARGET, "Unknown hunt.")
        if row["status"] != HuntStatus.INTERRUPTED.value:
            raise ToolError(ErrorCode.QUERY_REJECTED, "Only an interrupted hunt can be continued.")
        state = await self._repository.load_hunt_state(hunt_id)
        if not state or not state.get("messages"):
            raise ToolError(
                ErrorCode.UNKNOWN_TARGET,
                "No saved resumption state for this hunt.",
                hint="Use resumption as a new investigation.",
            )

        vault: TokenVault | None = None
        if state.get("vault") is not None:
            vault = TokenVault(internal_suffixes=self._settings.internal_hostname_suffixes)
            vault.load(state["vault"])
        saved_budget = state.get("budget") or {}
        limits = self._settings.budgets
        budgets = Budgets(
            max_iterations=min(
                max_iterations or saved_budget.get("max_iterations") or limits.max_iterations,
                PLATFORM_CAP,
            ),
            max_siem_queries=min(
                max_siem_queries or saved_budget.get("max_siem_queries") or limits.max_siem_queries,
                PLATFORM_CAP,
            ),
            max_tokens=limits.max_tokens,
            max_duration_seconds=limits.max_duration_seconds,
            token_alert_ratio=limits.token_alert_ratio,
        )
        window: tuple[datetime, datetime] | None = None
        if state.get("window"):
            try:
                window = (
                    datetime.fromisoformat(state["window"][0]),
                    datetime.fromisoformat(state["window"][1]),
                )
            except (ValueError, IndexError):
                window = None

        iocs = await self._repository.load_iocs(hunt_id)
        hunt = self._assemble(
            hunt_id=hunt_id,
            hypothesis=row["hypothesis"],
            campaign=row.get("campaign"),
            analyst=row["analyst"],
            iocs=iocs,
            status=HuntStatus.RUNNING,
            limits=budgets,
            sources=self._clients.available(),
            window=window,
            vault=vault,
        )
        hunt.budget.restore(
            iterations=saved_budget.get("iterations") or 0,
            siem_queries=saved_budget.get("siem_queries") or 0,
            tokens=saved_budget.get("tokens") or 0,
            elapsed_seconds=saved_budget.get("elapsed_seconds") or 0.0,
        )
        for record in state.get("records") or []:
            hunt.dossier.ledger.add(record_from_payload(record))
        hunt.dossier.findings = [
            Finding.model_validate(item) for item in state.get("findings") or []
        ]
        if row.get("playbook"):
            hunt.dossier.playbook = Playbook.model_validate(row["playbook"])
        hunt.dossier.parent_hunt_id = row.get("parent_hunt_id")
        hunt.dossier.resume_context = row.get("resume_context")
        hunt.orchestrator.seed_messages(state["messages"])
        self._hunts[hunt_id] = hunt

        await hunt.journal.record(
            AuditEventType.HUNT_CONTINUED,
            detail={
                "by": actor,
                "iterations_used": saved_budget.get("iterations"),
                "max_iterations": budgets.max_iterations,
                "max_siem_queries": budgets.max_siem_queries,
            },
        )
        hunt.dossier.status = HuntStatus.RUNNING
        await self._repository.set_status(hunt_id, HuntStatus.RUNNING)
        hunt.orchestrator.set_state_saver(self._state_saver_for(hunt))
        hunt.task = asyncio.create_task(self._run(hunt))
        return hunt

    @staticmethod
    def _refuse_if_running(hunt: ActiveHunt) -> None:
        """Indicators can no longer be modified once the loop is launched: the checkpoint
        has been cleared, the hunt reasons on a frozen validated set."""

        if hunt.running:
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "The hunt is in progress: its indicators can no longer be modified.",
                hint="Follow the investigation thread, or stop the hunt to start over.",
            )

    async def decide_budget(
        self,
        hunt_id: str,
        *,
        extend: bool,
        extra_iterations: int,
        extra_siem_queries: int,
        extra_minutes: int,
        actor: str,
    ) -> dict[str, Any]:
        """The analyst's decision at the budget checkpoint: continue with an extension, or
        stop cleanly. Logged and attributed, like any human validation."""

        hunt = self.get(hunt_id)
        if not hunt.orchestrator.awaiting_budget_decision:
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "This hunt is not awaiting a budget decision.",
            )
        if extend:
            hunt.budget.extend(
                extra_iterations=extra_iterations,
                extra_siem_queries=extra_siem_queries,
                extra_minutes=extra_minutes,
            )
        hunt.orchestrator.resolve_budget(extend=extend)
        await hunt.journal.record(
            AuditEventType.BUDGET_EVENT,
            detail={
                "action": "extension granted" if extend else "stop requested",
                "by": actor,
                "extra_iterations": extra_iterations if extend else 0,
                "extra_siem_queries": extra_siem_queries if extend else 0,
                "extra_minutes": extra_minutes if extend else 0,
            },
        )
        return {
            "hunt_id": hunt_id,
            "extended": extend,
            "budgets": hunt.budget.snapshot(),
        }

    async def stop(self, hunt_id: str) -> None:
        hunt = self.get(hunt_id)
        hunt.orchestrator.request_stop()

    async def delete(self, hunt_id: str, *, actor: str) -> bool:
        """Deletes a hunt from the history. Refuses a hunt in progress (stop it first).
        The operational data goes, the audit journal stays."""

        active = self._hunts.get(hunt_id)
        if active is not None and active.running:
            raise ToolError(
                ErrorCode.QUERY_REJECTED,
                "Cannot delete a hunt in progress; stop it first.",
            )
        removed = await self._repository.delete_hunt(hunt_id)
        if active is None and not removed:
            return False
        self._hunts.pop(hunt_id, None)
        journal = AuditJournal(self._audit_sink, hunt_id=hunt_id, actor=actor)
        await journal.record(AuditEventType.HUNT_DELETED, detail={})
        return True

    async def _run(self, hunt: ActiveHunt) -> HuntOutcome:
        outcome = await hunt.orchestrator.run()
        await self._repository.save_report(outcome.report)
        await self._repository.replace_iocs(hunt.dossier.hunt_id, hunt.dossier.iocs)
        if not outcome.interrupted:
            await self._repository.delete_hunt_state(hunt.dossier.hunt_id)
        return outcome

    def _budgets_for(self, request: CreateHuntRequest) -> Budgets:
        limits = self._settings.budgets
        return Budgets(
            max_iterations=min(request.max_iterations or limits.max_iterations, 100),
            max_siem_queries=min(request.max_siem_queries or limits.max_siem_queries, 100),
            max_tokens=limits.max_tokens,
            max_duration_seconds=limits.max_duration_seconds,
            token_alert_ratio=limits.token_alert_ratio,
        )

    def _selected_sources(self, request: CreateHuntRequest) -> list[str]:
        available = self._clients.available()
        if not request.sources:
            return available
        return [source for source in request.sources if source in available]

    # -- Source administration (Configuration screen, admin role) -----------------

    def describe_sources(self) -> list[SourceConfigView]:
        """State of each connector: configured, active, and what is missing. Never a value."""

        secrets = self._require_secrets()
        views: list[SourceConfigView] = []
        for definition in SOURCE_DEFINITIONS:
            fields = []
            for name in definition.secret_names:
                state = secrets.describe(name)
                fields.append(
                    SecretFieldView(
                        name=name,
                        configured=state["origin"] is not None,
                        origin=state["origin"],
                        updated_at=state.get("updated_at") or None,
                        updated_by=state.get("updated_by") or None,
                    )
                )
            active, requirement = self._source_state(definition, fields)
            endpoint, model = self._server_settings_for(definition.id)
            views.append(
                SourceConfigView(
                    id=definition.id,
                    label=definition.label,
                    kind=definition.kind,
                    active=active,
                    secrets=fields,
                    requirement=requirement,
                    endpoint=endpoint,
                    model=model,
                )
            )
        return views

    def _server_settings_for(self, source_id: str) -> tuple[str | None, str | None]:
        """Current endpoint and model for the sources that have one: shown to the admin so
        they know what is wired, without being editable from the screen (an egress
        destination stays a server decision)."""

        settings = self._settings
        match source_id:
            case "gateway":
                return (
                    settings.gateway_base_url or None,
                    f"{settings.gateway_model_query} / {settings.gateway_model_analysis}",
                )
            case "anonymizer":
                return (
                    settings.anonymizer_base_url or settings.gateway_base_url or None,
                    settings.anonymizer_model or None,
                )
            case _:
                return None, None

    async def update_secret(self, name: str, value: str, *, actor: str) -> None:
        secrets = self._require_secrets()
        key = self._configurable_name(name)
        if key == _DIRECT_WORKSPACE_ID and not _GUID_RE.match(value.strip()):
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                "The Workspace ID is a GUID (Log Analytics workspace overview, "
                "\"Workspace ID\" field), not the name or the resource identifier.",
            )
        secrets.set(key, value.strip(), actor=actor)
        await self._audit_config(
            AuditEventType.CONFIG_SECRET_UPDATED, actor=actor, detail={"secret": key}
        )
        if key in _WORKSPACE_FIELDS or key == _DIRECT_WORKSPACE_ID:
            try:
                await self.resolve_workspace(actor=actor)
            except ToolError:
                pass  # "Test the connection" will show the cause
        self._reload_sources()

    async def delete_secret(self, name: str, *, actor: str) -> bool:
        secrets = self._require_secrets()
        key = self._configurable_name(name)
        removed = secrets.delete(key)
        if removed:
            await self._audit_config(
                AuditEventType.CONFIG_SECRET_DELETED, actor=actor, detail={"secret": key}
            )
            if key in _WORKSPACE_FIELDS or key == _DIRECT_WORKSPACE_ID:
                await self.resolve_workspace(actor=actor)
            self._reload_sources()
        return removed

    async def test_source(self, source_id: str, *, actor: str) -> SourceTestResult:
        """Minimal real call to the source, to verify a key without ever reading it back."""

        try:
            detail = await self._run_source_test(source_id, actor=actor)
            result = SourceTestResult(source=source_id, ok=True, detail=detail)
        except ToolError as error:
            result = SourceTestResult(source=source_id, ok=False, detail=error.message)
        await self._audit_config(
            AuditEventType.CONFIG_SOURCE_TESTED,
            actor=actor,
            detail={"source": source_id, "ok": result.ok},
        )
        return result

    def _require_secrets(self) -> ConfigurableSecretProvider:
        if self._secrets is None:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "The configuration store is not available on this installation.",
            )
        return self._secrets

    def _configurable_name(self, name: str) -> str:
        key = name.strip().upper()
        if key not in CONFIGURABLE_SECRETS:
            raise ToolError(
                ErrorCode.UNKNOWN_TARGET,
                "This key does not exist in the source catalog.",
            )
        return key

    def _source_state(
        self, definition: SourceDefinition, fields: list[SecretFieldView]
    ) -> tuple[bool, str | None]:
        settings = self._settings
        configured = all(field.configured for field in fields)
        allowed = set(settings.ti_allowed_domains)

        match definition.id:
            case "gateway":
                if not settings.gateway_base_url:
                    return False, "SHL_GATEWAY_BASE_URL is not set on the server side."
                return configured, None if configured else "Key missing."
            case "anonymizer":
                if not (settings.anonymizer_base_url or settings.gateway_base_url):
                    return (
                        False,
                        "No anonymization endpoint: set SHL_ANONYMIZER_BASE_URL.",
                    )
                return configured, None if configured else "Anonymization key missing."
            case "entra":
                by_name = {field.name: field.configured for field in fields}
                if not all(by_name.get(name, False) for name in _ENTRA_IDENTITY_FIELDS):
                    return False, "Incomplete Entra ID credentials."
                if settings.workspace_aliases or by_name.get(_DIRECT_WORKSPACE_ID, False):
                    return True, None
                workspace = [by_name.get(name, False) for name in _WORKSPACE_FIELDS]
                if all(workspace):
                    return True, (
                        "Workspace entered but not yet resolved: run \"Test the connection\"."
                    )
                if any(workspace):
                    return True, (
                        "Incomplete Sentinel workspace: set Subscription ID, "
                        "resource group and workspace name. Only Defender is active."
                    )
                return True, (
                    "Without a Sentinel workspace (direct Workspace ID, or subscription + "
                    "resource group + name, or SHL_WORKSPACE_ALIASES on the server side), only "
                    "Defender is active."
                )
            case "secops":
                by_name = {field.name: field.configured for field in fields}
                if not by_name.get("SECOPS_SA_KEY", False):
                    return False, "Service account JSON key missing."
                has_path = by_name.get("SECOPS_INSTANCE_PATH", False) or bool(
                    settings.secops_instance_path
                )
                if not has_path:
                    return False, (
                        "Set the Instance ID (SECOPS_INSTANCE_PATH), visible in "
                        "the SecOps console (SOC Profile): "
                        "projects/<id>/locations/<region>/instances/<uuid>. The regional "
                        "endpoint is derived automatically."
                    )
                return True, None
            case "virustotal" | "otx" | "threatfox":
                return configured, None if configured else "Key missing."
            case "circl":
                if not {"www.circl.lu", "circl.lu"} & allowed:
                    return False, (
                        "Add www.circl.lu to SHL_TI_ALLOWED_DOMAINS (outbound allowlist, "
                        "editable only on the server side). No key required."
                    )
                return True, None
            case "publisher-reports":
                if not settings.ti_publisher_domains and not settings.ti_open_search:
                    return False, (
                        "Set SHL_TI_PUBLISHER_DOMAINS on the server side (publishers "
                        "approved by security), or SHL_TI_OPEN_SEARCH=true for "
                        "open search."
                    )
                by_name = {field.name: field.configured for field in fields}
                tavily = by_name.get("TAVILY_API_KEY", False)
                brave = by_name.get("BRAVE_SEARCH_API_KEY", False)
                google = by_name.get("SEARCH_API_KEY", False) and by_name.get(
                    "SEARCH_ENGINE_ID", False
                )
                if not tavily and not brave and not google:
                    return False, (
                        "Provide a search key: TAVILY_API_KEY (full web, "
                        "free tier - recommended), BRAVE_SEARCH_API_KEY (full "
                        "web, paid), or the Google pair SEARCH_API_KEY + "
                        "SEARCH_ENGINE_ID (engine limited to 50 domains)."
                    )
                if settings.ti_open_search:
                    return True, (
                        "Open search (SHL_TI_OPEN_SEARCH): any HTTPS page "
                        "found can be read. The egress allowlist is "
                        "deliberately relaxed for this source."
                    )
                return True, None
            case _:
                return False, None

    async def _run_source_test(self, source_id: str, *, actor: str) -> str:
        secrets = self._require_secrets()
        settings = self._settings

        match source_id:
            case "gateway":
                try:
                    completion = await self._gateway.complete(
                        model=settings.gateway_model_query,
                        messages=[{"role": "user", "content": "Reply only OK."}],
                        max_tokens=8,
                    )
                except ToolError as error:
                    raise _explain_gateway_refusal(
                        error,
                        endpoint=settings.gateway_base_url,
                        model=settings.gateway_model_query,
                        url_setting="SHL_GATEWAY_BASE_URL",
                        model_setting="SHL_GATEWAY_MODEL_QUERY",
                    ) from error
                return f"Gateway reached, response: {completion.content.strip()[:40]}"
            case "anonymizer":
                key = secrets.get_optional("ANONYMIZER_API_KEY")
                base = settings.anonymizer_base_url or settings.gateway_base_url
                if not key:
                    raise ToolError(ErrorCode.UNKNOWN_TARGET, "Anonymization key missing.")
                if not base:
                    raise ToolError(
                        ErrorCode.UNKNOWN_TARGET, "Anonymization endpoint not configured."
                    )
                client = GatewayClient(base_url=base, api_key=key, trust_proxy_env=False)
                try:
                    completion = await client.complete(
                        model=settings.anonymizer_model,
                        messages=[{"role": "user", "content": "Reply only OK."}],
                        max_tokens=8,
                    )
                except ToolError as error:
                    raise _explain_gateway_refusal(
                        error,
                        endpoint=base,
                        model=settings.anonymizer_model,
                        url_setting="SHL_ANONYMIZER_BASE_URL",
                        model_setting="SHL_ANONYMIZER_MODEL",
                    ) from error
                finally:
                    await client.aclose()
                return (
                    f"Anonymization model {settings.anonymizer_model} reached, "
                    f"response: {completion.content.strip()[:40]}"
                )
            case "entra":
                try:
                    resolved = await self.resolve_workspace(actor=actor)
                except ToolError as error:
                    if error.code is ErrorCode.UPSTREAM_REJECTED:
                        raise ToolError(
                            error.code,
                            f"Workspace not resolved: {error.message} The app registration has "
                            "no read role on this workspace: request Log Analytics "
                            "Reader at the workspace level, or enter the "
                            "Workspace ID (GUID) directly above.",
                        ) from error
                    raise
                self._reload_sources()
                provider = self._entra_provider(secrets)
                try:
                    await provider.token_for("https://graph.microsoft.com/.default")
                    if not settings.workspace_aliases:
                        return "Application token obtained from Entra ID (Defender only)."
                    sentinel = SentinelClient(token_provider=provider)
                    try:
                        for alias, workspace_id in settings.workspace_aliases.items():
                            try:
                                await sentinel.run_query(
                                    query="print now()",
                                    workspace_id=workspace_id,
                                    timespan_days=1,
                                    row_cap=1,
                                )
                            except ToolError as error:
                                raise ToolError(
                                    error.code,
                                    f"Token obtained, but the workspace \"{alias}\" responds: "
                                    f"{error.message}",
                                    hint=error.hint
                                    or (
                                        "Check the Workspace ID (GUID) in "
                                        "SHL_WORKSPACE_ALIASES and the app registration's "
                                        "Log Analytics Reader role on this workspace."
                                    ),
                                ) from error
                    finally:
                        await sentinel.aclose()
                finally:
                    await provider.aclose()
                names = ", ".join(sorted(settings.workspace_aliases))
                suffix = (
                    f" Workspace resolved from its name (ID ending in {resolved[-4:]})."
                    if resolved
                    else ""
                )
                return f"Token obtained and read confirmed on: {names}.{suffix}"
            case "secops":
                raw_key = secrets.get_optional("SECOPS_SA_KEY")
                if not raw_key:
                    raise ToolError(
                        ErrorCode.UNKNOWN_TARGET, "Service account JSON key missing."
                    )
                raw_path = (
                    secrets.get_optional("SECOPS_INSTANCE_PATH") or settings.secops_instance_path
                )
                endpoint_note = ""
                if raw_path:
                    _, base_url = resolve_instance(raw_path, settings.secops_base_url)
                    endpoint_note = f" Endpoint: {base_url}."
                gcp = GcpTokenProvider(GcpCredentials.from_service_account_json(raw_key))
                try:
                    await gcp.token_for(SECOPS_SCOPE)
                finally:
                    await gcp.aclose()
                return f"Access token obtained for the SecOps service account.{endpoint_note}"
            case _:
                source = self._ti_source_for_test(source_id, secrets)
                iocs = await source.search("Volt Typhoon", limit=5)
                return f"Source reached, {len(iocs)} indicator(s) on the test campaign."

    def _entra_provider(self, secrets: SecretProvider) -> EntraTokenProvider:
        tenant = secrets.get_optional("ENTRA_TENANT_ID")
        client_id = secrets.get_optional("ENTRA_CLIENT_ID")
        client_secret = secrets.get_optional("ENTRA_CLIENT_SECRET")
        if not (tenant and client_id and client_secret):
            raise ToolError(ErrorCode.UNKNOWN_TARGET, "Incomplete Entra ID credentials.")
        return EntraTokenProvider(
            EntraCredentials(tenant_id=tenant, client_id=client_id, client_secret=client_secret)
        )

    def _ti_source_for_test(self, source_id: str, secrets: SecretProvider) -> ThreatIntelSource:
        settings = self._settings
        allowed = set(settings.ti_allowed_domains)

        def _key(name: str) -> str:
            value = secrets.get_optional(name)
            if not value:
                raise ToolError(ErrorCode.UNKNOWN_TARGET, "Key missing for this source.")
            return value

        match source_id:
            case "virustotal":
                return VirusTotalSource(_key("VIRUSTOTAL_API_KEY"))
            case "otx":
                return OtxSource(_key("OTX_API_KEY"))
            case "threatfox":
                return ThreatFoxSource(_key("THREATFOX_API_KEY"))
            case "circl":
                if not {"www.circl.lu", "circl.lu"} & allowed:
                    raise ToolError(
                        ErrorCode.EGRESS_BLOCKED,
                        "www.circl.lu is not in the outbound allowlist.",
                    )
                return MispFeedSource()
            case "publisher-reports":
                if not settings.ti_publisher_domains and not settings.ti_open_search:
                    raise ToolError(
                        ErrorCode.EGRESS_BLOCKED,
                        "No approved publisher in SHL_TI_PUBLISHER_DOMAINS "
                        "(or enable SHL_TI_OPEN_SEARCH on the server side).",
                    )
                config = _search_provider_config(secrets)
                if config is None:
                    raise ToolError(
                        ErrorCode.UNKNOWN_TARGET,
                        "No search key configured (Tavily, Brave or Google).",
                    )
                provider, api_key, engine_id = config
                return WebReportSource(
                    search_api_key=api_key,
                    search_engine_id=engine_id,
                    publisher_domains=settings.ti_publisher_domains,
                    gateway=self._gateway,
                    model=settings.gateway_model_query,
                    open_search=settings.ti_open_search,
                    search_provider=provider,
                )
            case _:
                raise ToolError(ErrorCode.UNKNOWN_TARGET, "Unknown source.")

    def _reload_sources(self) -> None:
        """Rebuilds the connectors with the current keys. Hunts in flight keep their
        clients; hunts created afterwards see the new configuration."""

        secrets = self._secrets
        if secrets is None:
            return
        self._apply_workspace_aliases()
        self._clients = build_clients(self._settings, secrets)
        if self._settings.gateway_base_url:
            previous = self._gateway
            self._gateway = GatewayClient(
                base_url=self._settings.gateway_base_url,
                api_key=secrets.get_optional("GATEWAY_API_KEY") or "",
                prompt_caching=self._settings.gateway_prompt_caching,
            )
            if isinstance(previous, GatewayClient):
                task = asyncio.create_task(previous.aclose())
                task.add_done_callback(lambda _: None)
        self._threat_intel = build_threat_intel(self._settings, secrets, self._gateway)

    async def analyze_cti_report(self, data: bytes, *, filename: str, actor: str) -> dict[str, Any]:
        """Analyzes a CTI report (PDF) provided by the analyst: summary of the described
        attacks and hunt proposals. Content treated as untrusted, IOCs revalidated by
        pattern. No outbound flow: the document comes from the analyst."""

        if self._gateway is None:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "The reasoning engine is not configured on this installation.",
            )
        text, pages, truncated = extract_pdf_text(data)
        attacks = await analyze_report_text(
            text,
            gateway=self._gateway,
            model=self._settings.gateway_model_analysis,
            source_name=filename,
        )
        analysis_id = f"cti_{uuid.uuid4().hex[:12]}"
        await self._repository.save_cti_analysis(
            analysis_id=analysis_id,
            filename=filename,
            analyzed_by=actor,
            analyzed_at=datetime.now(UTC).isoformat(),
            pages=pages,
            truncated=truncated,
            attacks=attacks,
        )
        await self.record_platform_event(
            AuditEventType.CTI_REPORT_ANALYZED,
            actor=actor,
            detail={
                "analysis_id": analysis_id,
                "filename": filename,
                "pages": pages,
                "attacks": len(attacks),
                "iocs": sum(len(attack["iocs"]) for attack in attacks),
            },
        )
        return {
            "analysis_id": analysis_id,
            "attacks": attacks,
            "pages": pages,
            "truncated": truncated,
        }

    async def probe_iocs(
        self,
        campaign_name: str,
        *,
        actor: str,
        analysis_id: str | None = None,
        attack_index: int | None = None,
    ) -> dict[str, Any]:
        """Probe for IOC availability for a campaign, without creating a hunt.

        Same path as enrichment (only authorized outbound flow, anti-leak filter
        included): it serves to decide the hunt approach - by indicators if threat
        intelligence publishes any, by hypothesis otherwise. The IOCs found are kept in
        cache for 15 minutes: a hunt created right after on the same threat carries them.
        """

        if self._threat_intel is None or not self._threat_intel.enabled:
            raise ToolError(
                ErrorCode.EGRESS_BLOCKED,
                "No threat intelligence source is enabled on this installation.",
            )
        found, _dropped = await self._threat_intel.search(campaign_name, max_results=15)
        self._probe_cache[campaign_name.strip().lower()] = (time.monotonic(), found)
        sources: list[str] = []
        for ioc in found:
            if ioc.source_name not in sources:
                sources.append(ioc.source_name)
        await self.record_platform_event(
            AuditEventType.IOC_SEARCH,
            actor=actor,
            detail={"campaign": campaign_name, "found": len(found), "context": "cti_probe"},
        )
        result = {
            "found": len(found),
            "sources": sources[:6],
            "sample": [{"value": ioc.value, "type": ioc.type.value} for ioc in found[:5]],
        }
        if analysis_id is not None and attack_index is not None:
            await self._repository.set_cti_probe(analysis_id, attack_index, result)
        return result

    async def record_platform_event(
        self, event_type: AuditEventType, *, actor: str, detail: dict[str, Any]
    ) -> None:
        """Audit event outside a hunt (configuration, authentication), under the identifier
        `platform`."""

        journal = AuditJournal(self._audit_sink, hunt_id=_PLATFORM_AUDIT_ID, actor=actor)
        await journal.record(event_type, detail=detail)

    async def _audit_config(
        self, event_type: AuditEventType, *, actor: str, detail: dict[str, Any]
    ) -> None:
        await self.record_platform_event(event_type, actor=actor, detail=detail)


_RESUME_MAX_QUERIES = 30
_RESUME_TEXT_CAP = 220


def _resume_line(index: int, siem: str, label: str, rows: object, truncated: object) -> str:
    flag = ", truncated" if truncated else ""
    label = " ".join(str(label).split())
    if len(label) > _RESUME_TEXT_CAP:
        label = label[: _RESUME_TEXT_CAP - 1] + "…"
    return f"{index}. [{siem}] {label} - {rows} row(s){flag}"


def build_resume_context(
    *,
    parent_id: str,
    row: dict[str, Any],
    report: HuntReport | None,
    audit: list[dict[str, Any]],
    from_query_id: str | None,
    instruction: str | None,
) -> str:
    """Timeline of the parent hunt, rebuilt from what is persisted: the report when it
    exists (query intents included), otherwise the audit journal - a hunt cut down by a
    restart has no report but its journal is complete."""

    lines = [f"Resumption of hunt {parent_id}."]
    if row["status"] == HuntStatus.INTERRUPTED.value:
        reason = row.get("interruption_reason") or "reason not specified"
        lines.append(f"This hunt was interrupted: {reason}.")
    playbook = row.get("playbook")
    if isinstance(playbook, dict) and playbook.get("summary"):
        lines.extend(["", "### Initial plan", str(playbook.get("summary"))])

    entries: list[tuple[str, str, str, object, object]] = []
    if report is not None and report.executed_queries:
        for query in report.executed_queries:
            first_line = next(
                (part.strip() for part in query.query.splitlines() if part.strip()), ""
            )
            entries.append(
                (
                    query.query_id,
                    query.siem,
                    query.intent or first_line,
                    query.returned_rows,
                    query.truncated,
                )
            )
    else:
        for event in audit:
            if event.get("type") != AuditEventType.QUERY_EXECUTED.value:
                continue
            first_line = next(
                (
                    part.strip()
                    for part in str(event.get("query") or "").splitlines()
                    if part.strip()
                ),
                "",
            )
            entries.append(
                (
                    str(event.get("query_id") or ""),
                    str(event.get("siem") or ""),
                    first_line,
                    event.get("rows_returned"),
                    event.get("truncated"),
                )
            )
    if from_query_id:
        known = [entry[0] for entry in entries]
        if from_query_id not in known:
            raise ToolError(
                ErrorCode.UNKNOWN_TARGET,
                f"The query {from_query_id} does not belong to the hunt {parent_id}.",
            )
        entries = entries[: known.index(from_query_id) + 1]
        lines.append(
            f"The resumption starts after the query {from_query_id}: the following queries "
            "of the initial hunt are deliberately ignored."
        )
    if entries:
        lines.extend(["", "### Queries already executed", ""])
        shown = entries[-_RESUME_MAX_QUERIES:]
        if len(entries) > len(shown):
            lines.append(f"({len(entries) - len(shown)} older query(ies) omitted)")
        for index, (query_id, siem, label, rows, truncated) in enumerate(shown, 1):
            lines.append(_resume_line(index, siem, f"{query_id} · {label}", rows, truncated))
    included = {entry[0] for entry in entries}
    if report is not None and report.findings:
        kept = [
            finding
            for finding in report.findings
            if not from_query_id
            or all(query_id in included for query_id in finding.evidence_query_ids)
        ]
        if kept:
            lines.extend(["", "### Findings already recorded", ""])
            for finding in kept:
                lines.append(f"- [{finding.severity.value}] {finding.title}")
    if report is not None and not from_query_id:
        lines.extend(["", "### Conclusion of the initial hunt", "", report.summary])
        if report.limitations:
            lines.append(f"Limitations noted: {report.limitations}")
    if instruction and instruction.strip():
        lines.extend(
            [
                "",
                "### Analyst's question for this resumption",
                "",
                instruction.strip(),
            ]
        )
    return "\n".join(lines)


def build_clients(settings: Settings, secrets: SecretProvider) -> SiemClients:
    """Instantiates the clients whose credentials are actually available."""

    if settings.demo_siem:
        if settings.environment != "dev":
            raise RuntimeError(
                "The simulated SIEM mode (SHL_DEMO_SIEM) is forbidden outside the dev environment."
            )
        return SiemClients(
            sentinel=SimulatedSiemClient(siem="sentinel"),
            defender=SimulatedSiemClient(siem="defender"),
            secops=SimulatedSiemClient(siem="secops"),
        )

    clients = SiemClients()

    tenant = secrets.get_optional("ENTRA_TENANT_ID")
    client_id = secrets.get_optional("ENTRA_CLIENT_ID")
    client_secret = secrets.get_optional("ENTRA_CLIENT_SECRET")
    if tenant and client_id and client_secret:
        provider = EntraTokenProvider(
            EntraCredentials(tenant_id=tenant, client_id=client_id, client_secret=client_secret)
        )
        if settings.workspace_aliases:
            clients.sentinel = SentinelClient(token_provider=provider)
        clients.defender = DefenderClient(token_provider=provider)

    secops_key = secrets.get_optional("SECOPS_SA_KEY")
    raw_path = secrets.get_optional("SECOPS_INSTANCE_PATH") or settings.secops_instance_path
    if secops_key and raw_path:
        try:
            credentials = GcpCredentials.from_service_account_json(secops_key)
            instance_path, base_url = resolve_instance(raw_path, settings.secops_base_url)
        except ToolError:
            pass  # unreadable key or path: SecOps stays inactive, the source test will say so
        else:
            clients.secops = SecOpsClient(
                token_provider=GcpTokenProvider(credentials),
                base_url=base_url,
                instance_path=instance_path,
            )

    return clients


def _search_provider_config(secrets: SecretProvider) -> tuple[str, str, str] | None:
    """(provider, key, engine id) depending on the keys present. Priority: Tavily (free
    tier), Brave, then Google (engine limited to 50 domains since 2026)."""

    tavily = secrets.get_optional("TAVILY_API_KEY")
    if tavily:
        return ("tavily", tavily, "")
    brave = secrets.get_optional("BRAVE_SEARCH_API_KEY")
    if brave:
        return ("brave", brave, "")
    search_key = secrets.get_optional("SEARCH_API_KEY")
    engine_id = secrets.get_optional("SEARCH_ENGINE_ID")
    if search_key and engine_id:
        return ("google", search_key, engine_id)
    return None


def build_threat_intel(
    settings: Settings,
    secrets: SecretProvider,
    gateway: GatewayClient | None = None,
) -> ThreatIntelConnector | None:
    """Assembles the connector from the sources actually configured.

    Fixed-domain sources (VirusTotal, OTX, ThreatFox) activate as soon as their key is
    present: their domain is hardcoded, reviewed and validated, so the key is enough - no
    allowlist to maintain in duplicate. The "vendor reports" source is an exception: it
    queries domains chosen by the admin (`SHL_TI_PUBLISHER_DOMAINS`), an arbitrary outbound
    flow that remains a server decision validated by security.
    """

    sources: list[ThreatIntelSource] = []

    virustotal_key = secrets.get_optional("VIRUSTOTAL_API_KEY")
    if virustotal_key:
        sources.append(VirusTotalSource(virustotal_key))

    otx_key = secrets.get_optional("OTX_API_KEY")
    if otx_key:
        sources.append(OtxSource(otx_key))

    threatfox_key = secrets.get_optional("THREATFOX_API_KEY")
    if threatfox_key:
        sources.append(ThreatFoxSource(threatfox_key))

    if {"www.circl.lu", "circl.lu"} & set(settings.ti_allowed_domains):
        sources.append(MispFeedSource())

    search_config = _search_provider_config(secrets)
    if search_config and gateway and (settings.ti_publisher_domains or settings.ti_open_search):
        provider, api_key, engine_id = search_config
        sources.append(
            WebReportSource(
                search_api_key=api_key,
                search_engine_id=engine_id,
                publisher_domains=settings.ti_publisher_domains,
                gateway=gateway,
                model=settings.gateway_model_query,
                open_search=settings.ti_open_search,
                search_provider=provider,
            )
        )

    if not sources:
        return None

    allowed = set(settings.ti_allowed_domains) | set(settings.ti_publisher_domains)
    for source in sources:
        allowed.update(source.covered_domains())
    return ThreatIntelConnector(
        sources,
        allowed_domains=tuple(allowed),
        internal_suffixes=settings.internal_hostname_suffixes,
        open_sources=settings.ti_open_search,
    )

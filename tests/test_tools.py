import pytest

from middleware.audit import AuditJournal, MemoryAuditSink
from middleware.budgets import HuntBudget
from middleware.clients.results import QueryOutcome
from middleware.config import Budgets, Settings
from middleware.errors import BudgetExhausted, ErrorCode
from middleware.executor import QueryLedger, SiemExecutor
from reporting.dossier import Dossier
from reporting.models import HuntStatus, Verdict
from tools.definitions import build_enrichment_registry, build_registry

EXPECTED_TOOLS = {
    "conclude_hunt",
    "record_finding",
    "run_defender_hunting",
    "run_secops_query",
    "run_sentinel_kql",
}


class FakeSentinel:
    async def run_query(self, *, query, workspace_id, timespan_days, row_cap):
        return QueryOutcome(rows=[{"Account": "svc"}], duration_ms=5)


@pytest.fixture
def context():
    sink = MemoryAuditSink()
    journal = AuditJournal(sink, hunt_id="hunt_1", actor="j.doe")
    ledger = QueryLedger()
    settings = Settings(_env_file=None, workspace_aliases={"soc": "guid-real"})
    executor = SiemExecutor(
        settings=settings,
        journal=journal,
        budget=HuntBudget(limits=Budgets()),
        ledger=ledger,
        sentinel=FakeSentinel(),
        limiters={},
    )
    dossier = Dossier(hunt_id="hunt_1", hypothesis="Volt Typhoon", analyst="j.doe")
    dossier.ledger = ledger
    registry = build_registry(executor=executor, dossier=dossier, journal=journal)
    return registry, dossier, sink


class TestClosedToolSurface:
    def test_exact_tool_list(self, context):
        registry, _, _ = context
        assert set(registry.names) == EXPECTED_TOOLS

    def test_no_egress_tool_is_exposed_to_the_model(self, context):
        """The only outbound flow (threat intel) does not exist in the model's registry.

        A string read from a log can therefore never become an outbound query, even on a
        successful prompt injection: the tool is not there.
        """

        registry, _, _ = context
        assert "get_iocs_for_campaign" not in registry.names

    async def test_egress_tool_is_not_callable_even_by_name(self, context):
        registry, _, _ = context
        result = await registry.dispatch("get_iocs_for_campaign", {"campaign_name": "Volt Typhoon"})
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value

    def test_no_write_or_response_tool_exists(self, context):
        registry, _, _ = context
        forbidden = (
            "isolate",
            "block",
            "disable",
            "quarantine",
            "remediat",
            "create",
            "update",
            "delete",
            "write",
            "set_",
        )
        assert not [name for name in registry.names if any(word in name for word in forbidden)]

    def test_unknown_tool_is_refused(self, context):
        registry, _, _ = context
        assert registry.names and "isolate_host" not in registry.names

    async def test_calling_an_unknown_tool_returns_a_structured_error(self, context):
        registry, _, _ = context
        result = await registry.dispatch("isolate_host", {"device": "host-1"})
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value

    def test_schemas_are_strict(self, context):
        registry, _, _ = context
        for schema in registry.function_schemas():
            assert schema["function"]["parameters"]["additionalProperties"] is False


class TestSchemaValidation:
    async def test_extra_argument_is_refused(self, context):
        registry, _, _ = context
        result = await registry.dispatch(
            "run_sentinel_kql",
            {
                "kql_query": "SigninLogs",
                "workspace": "soc",
                "intent": "Service account connections over the period",
                "callback_url": "https://x.example",
            },
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value

    async def test_out_of_range_value_is_refused_before_execution(self, context):
        registry, _, _ = context
        result = await registry.dispatch(
            "run_sentinel_kql",
            {
                "kql_query": "SigninLogs",
                "workspace": "soc",
                "intent": "Service account connections over the period",
                "max_rows": 100000,
            },
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value

    async def test_timespan_beyond_api_limit_is_refused(self, context):
        registry, _, _ = context
        result = await registry.dispatch(
            "run_defender_hunting",
            {
                "kql_query": "DeviceEvents",
                "intent": "Service account connections over the period",
                "timespan_days": 90,
            },
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value


class TestIntent:
    async def test_intent_is_mandatory_on_siem_tools(self, context):
        registry, _, _ = context
        result = await registry.dispatch(
            "run_sentinel_kql", {"kql_query": "SigninLogs", "workspace": "soc"}
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value
        assert "intent" in result["message"]

    async def test_intent_and_sample_are_kept_for_the_analyst(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "run_sentinel_kql",
            {
                "kql_query": "SigninLogs",
                "workspace": "soc",
                "intent": "Spot off-hours connections",
            },
        )
        record = dossier.ledger.records[result["query_id"]]
        assert record.intent == "Spot off-hours connections"
        assert record.columns == ("Account",)
        assert record.sample == ({"Account": "svc"},)
        executed = dossier.executed_queries()[0]
        assert executed.intent == record.intent
        assert executed.sample == [{"Account": "svc"}]


class TestEvidenceRequirement:
    async def test_finding_without_evidence_is_refused(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "record_finding",
            {
                "title": "Suspicious connection",
                "description": "A service account connects outside business hours.",
                "severity": "medium",
                "confidence": "medium",
                "evidence_query_ids": [],
            },
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value
        assert dossier.findings == []

    async def test_finding_citing_an_unknown_query_is_refused(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "record_finding",
            {
                "title": "Suspicious connection",
                "description": "A service account connects outside business hours.",
                "severity": "medium",
                "confidence": "medium",
                "evidence_query_ids": ["q_nonexistent"],
            },
        )
        assert result["error"] == ErrorCode.EVIDENCE_MISSING.value
        assert dossier.findings == []

    async def test_finding_citing_a_real_query_is_accepted(self, context):
        registry, dossier, _ = context
        executed = await registry.dispatch(
            "run_sentinel_kql",
            {
                "kql_query": "SigninLogs",
                "workspace": "soc",
                "intent": "Service account connections over the period",
            },
        )
        result = await registry.dispatch(
            "record_finding",
            {
                "title": "Suspicious connection",
                "description": "A service account connects outside business hours.",
                "severity": "medium",
                "confidence": "medium",
                "evidence_query_ids": [executed["query_id"]],
            },
        )
        assert result["recorded"] is True
        assert dossier.findings[0].evidence_query_ids == [executed["query_id"]]


class TestConclusion:
    async def test_limitations_are_mandatory(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "conclude_hunt",
            {"verdict": "benign", "summary": "No signal over the hunt's analyzed period."},
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value
        assert dossier.conclusion is None

    async def test_conclusion_moves_the_hunt_to_human_review(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "conclude_hunt",
            {
                "verdict": "suspicious",
                "summary": "Three off-hours connections on a service account.",
                "limitations": "Defender not covered beyond 30 days.",
            },
        )
        assert result["proposed_verdict"] == Verdict.SUSPICIOUS.value
        assert dossier.status is HuntStatus.AWAITING_REVIEW

    async def test_attack_presentation_is_kept_with_the_conclusion(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "conclude_hunt",
            {
                "verdict": "benign",
                "summary": "No signal over the hunt's analyzed period.",
                "limitations": "Defender not covered beyond 30 days.",
                "attack_description": (
                    "An attacker already present abuses WMI and PowerShell to move "
                    "without dropping a binary."
                ),
                "techniques": [
                    {"id": "T1047", "name": "Execution via WMI", "description": "wmic /node."}
                ],
                "recommendation": "No action, monitoring maintained.",
            },
        )
        assert "error" not in result
        assert dossier.conclusion is not None
        assert dossier.conclusion.techniques[0].id == "T1047"
        assert dossier.conclusion.recommendation == "No action, monitoring maintained."

    async def test_technique_ids_must_look_like_mitre_ids(self, context):
        registry, dossier, _ = context
        result = await registry.dispatch(
            "conclude_hunt",
            {
                "verdict": "benign",
                "summary": "No signal over the hunt's analyzed period.",
                "limitations": "Defender not covered beyond 30 days.",
                "techniques": [{"id": "WMI", "name": "Execution via WMI", "description": "x" * 12}],
            },
        )
        assert result["error"] == ErrorCode.SCHEMA_INVALID.value
        assert dossier.conclusion is None


class TestWorkspaceAliasesAreDeclared:
    def test_sentinel_tool_lists_valid_aliases(self):
        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_1", actor="a")
        executor = SiemExecutor(
            settings=Settings(_env_file=None, workspace_aliases={"soc-principal": "guid"}),
            journal=journal,
            budget=HuntBudget(limits=Budgets()),
            ledger=QueryLedger(),
            limiters={},
        )
        dossier = Dossier(hunt_id="hunt_1", hypothesis="x", analyst="a")
        registry = build_registry(
            executor=executor, dossier=dossier, journal=journal, workspaces=("soc-principal",)
        )
        schema = next(
            s for s in registry.function_schemas() if s["function"]["name"] == "run_sentinel_kql"
        )
        assert "soc-principal" in schema["function"]["description"]


class TestEnrichmentRegistry:
    def _enrichment(self):
        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_1", actor="j.doe")
        dossier = Dossier(hunt_id="hunt_1", hypothesis="Volt Typhoon", analyst="j.doe")
        return build_enrichment_registry(dossier=dossier, journal=journal)

    def test_only_the_threat_intel_tool_exists(self):
        assert self._enrichment().names == ["get_iocs_for_campaign"]

    async def test_no_source_configured_blocks_egress(self):
        result = await self._enrichment().dispatch(
            "get_iocs_for_campaign", {"campaign_name": "Volt Typhoon"}
        )
        assert result["error"] == ErrorCode.EGRESS_BLOCKED.value

    async def test_research_refreshes_pending_but_never_decided_iocs(self):
        """Re-running the search refreshes the attribution of pending indicators;
        those the analyst has decided or supplied themselves do not move."""

        from middleware.guardrails.ioc import Ioc, IocStatus, IocType

        class FakeConnector:
            def __init__(self):
                self.enabled = True
                self.round = 0

            async def search(self, campaign, *, ioc_types=None, max_results, time_range=None):
                self.round += 1
                source = "aggregator.example" if self.round == 1 else "Official publisher"
                url = (
                    "https://aggregator.example/copy"
                    if self.round == 1
                    else "https://publisher.example/report"
                )
                return (
                    [
                        Ioc(
                            value="evil.example",
                            type=IocType.DOMAIN,
                            source_name=source,
                            source_url=url,
                        ),
                        Ioc(
                            value="frozen.example",
                            type=IocType.DOMAIN,
                            source_name=source,
                            source_url=url,
                        ),
                    ],
                    [],
                )

        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_1", actor="j.doe")
        dossier = Dossier(hunt_id="hunt_1", hypothesis="MacSync", analyst="j.doe")
        registry = build_enrichment_registry(
            dossier=dossier, journal=journal, threat_intel=FakeConnector()
        )

        await registry.dispatch("get_iocs_for_campaign", {"campaign_name": "MacSync"})
        dossier.iocs[1].status = IocStatus.VALIDATED

        await registry.dispatch("get_iocs_for_campaign", {"campaign_name": "MacSync"})

        refreshed = next(ioc for ioc in dossier.iocs if ioc.value == "evil.example")
        decided = next(ioc for ioc in dossier.iocs if ioc.value == "frozen.example")
        assert refreshed.source_name == "Official publisher"
        assert refreshed.status is IocStatus.PENDING_VALIDATION
        assert decided.source_name == "aggregator.example"
        assert decided.status is IocStatus.VALIDATED
        assert len(dossier.iocs) == 2


class TestBudgetPropagates:
    async def test_budget_exhaustion_is_not_swallowed(self):
        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_1", actor="a")
        ledger = QueryLedger()
        executor = SiemExecutor(
            settings=Settings(_env_file=None, workspace_aliases={"soc": "guid"}),
            journal=journal,
            budget=HuntBudget(limits=Budgets(max_siem_queries=0)),
            ledger=ledger,
            sentinel=FakeSentinel(),
            limiters={},
        )
        dossier = Dossier(hunt_id="hunt_1", hypothesis="h", analyst="a")
        dossier.ledger = ledger
        registry = build_registry(executor=executor, dossier=dossier, journal=journal)

        with pytest.raises(BudgetExhausted):
            await registry.dispatch(
                "run_sentinel_kql",
                {
                    "kql_query": "SigninLogs",
                    "workspace": "soc",
                    "intent": "Service account connections over the period",
                },
            )

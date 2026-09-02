"""Tokenization: internal identifiers never leave the platform.

Three boundaries tested: SIEM results are tokenized before being returned to the model,
the model's queries are detokenized before execution, and both the findings and the
conclusion are rehydrated for the analyst.
"""

from middleware.audit import AuditJournal, MemoryAuditSink
from middleware.budgets import HuntBudget
from middleware.clients.results import QueryOutcome
from middleware.config import Budgets, Settings
from middleware.executor import QueryLedger, SiemExecutor
from middleware.minimization import mask_row
from middleware.tokenization import TokenVault
from reporting.dossier import Dossier
from tools.definitions import build_registry


class TestTokenVault:
    def test_tokens_are_stable_and_typed(self):
        vault = TokenVault()
        assert vault.token_for("host", "PARIS-DC-01") == "HOST-001"
        assert vault.token_for("host", "paris-dc-01") == "HOST-001"
        assert vault.token_for("host", "LYON-SRV-02") == "HOST-002"
        assert vault.token_for("user", "svc-backup") == "USER-001"

    def test_detokenize_restores_originals(self):
        vault = TokenVault()
        vault.token_for("host", "PARIS-DC-01")
        vault.token_for("user", "svc-backup")

        text = "Connection from USER-001 on HOST-001, then pivot to HOST-999."
        restored = vault.detokenize_text(text)

        assert "svc-backup" in restored
        assert "PARIS-DC-01" in restored
        assert "HOST-999" in restored

    def test_free_text_replaces_known_values_private_ips_and_suffixes(self):
        vault = TokenVault(internal_suffixes=("corp.example",))
        vault.token_for("host", "PARIS-DC-01")

        text = (
            "PARIS-DC-01 (10.20.30.40) contacted 45.155.12.7 then fileserver.corp.example replied."
        )
        tokenized = vault.tokenize_text(text)

        assert "PARIS-DC-01" not in tokenized
        assert "10.20.30.40" not in tokenized
        assert "IP-INT-001" in tokenized
        assert "45.155.12.7" in tokenized
        assert "fileserver.corp.example" not in tokenized

    def test_public_ip_is_never_tokenized(self):
        vault = TokenVault()
        assert vault.tokenize_text("C2 at 45.155.12.7") == "C2 at 45.155.12.7"


class TestMaskRowIntegration:
    def test_host_and_user_fields_are_tokenized(self):
        settings = Settings(_env_file=None)
        vault = TokenVault()
        row = {
            "Computer": "PARIS-DC-01",
            "Account": "svc-backup",
            "CommandLine": "ping PARIS-DC-01",
            "password": "hunter2",
        }
        masked = mask_row(row, settings.masking, tokenization=settings.tokenization, vault=vault)

        assert masked["Computer"] == "HOST-001"
        assert masked["Account"] == "USER-001"
        assert "PARIS-DC-01" not in masked["CommandLine"]
        assert "password" not in masked


def _executor(settings, vault, captured):
    class FakeSentinel:
        async def run_query(self, *, query, workspace_id, timespan_days, row_cap):
            captured.append(query)
            return QueryOutcome(
                rows=[{"Computer": "PARIS-DC-01", "Account": "svc-backup"}],
                duration_ms=3,
            )

    journal = AuditJournal(MemoryAuditSink(), hunt_id="hunt_test", actor="test")
    return SiemExecutor(
        settings=settings,
        journal=journal,
        budget=HuntBudget(limits=Budgets()),
        ledger=QueryLedger(),
        sentinel=FakeSentinel(),
        vault=vault,
    )


class TestExecutorBoundary:
    async def test_outgoing_query_is_detokenized_and_results_tokenized(self):
        settings = Settings(_env_file=None, workspace_aliases={"soc": "guid"})
        vault = TokenVault()
        vault.token_for("host", "PARIS-DC-01")
        captured = []

        payload = await _executor(settings, vault, captured).run_sentinel(
            kql_query="SigninLogs | where Computer == 'HOST-001'",
            workspace="soc",
        )

        assert len(captured) == 1
        assert "Computer == 'PARIS-DC-01'" in captured[0]
        assert "HOST-001" not in captured[0]
        assert "PARIS-DC-01" not in str(payload)
        assert "svc-backup" not in str(payload)
        assert "HOST-001" in payload["executed_query"]

    async def test_disabled_tokenization_passes_through(self):
        settings = Settings(_env_file=None, workspace_aliases={"soc": "guid"})
        settings.tokenization.enabled = False
        captured = []

        payload = await _executor(settings, TokenVault(), captured).run_sentinel(
            kql_query="SigninLogs | take 5",
            workspace="soc",
        )

        assert "PARIS-DC-01" in str(payload)


class TestDossierRehydration:
    def _registry_and_dossier(self, vault):
        settings = Settings(_env_file=None, workspace_aliases={"soc": "guid"})
        journal = AuditJournal(MemoryAuditSink(), hunt_id="hunt_test", actor="test")
        ledger = QueryLedger()
        executor = SiemExecutor(
            settings=settings,
            journal=journal,
            budget=HuntBudget(limits=Budgets()),
            ledger=ledger,
            vault=vault,
        )
        dossier = Dossier(hunt_id="hunt_test", hypothesis="test", analyst="a", ledger=ledger)
        registry = build_registry(executor=executor, dossier=dossier, journal=journal, vault=vault)
        return registry, dossier, ledger

    async def test_findings_are_stored_with_real_values(self):
        vault = TokenVault()
        vault.token_for("host", "PARIS-DC-01")
        vault.token_for("user", "svc-backup")
        registry, dossier, ledger = self._registry_and_dossier(vault)

        from middleware.executor import QueryRecord

        ledger.add(
            QueryRecord(
                query_id="q_1",
                siem="sentinel",
                query="SigninLogs",
                executed_at="2026-01-01T00:00:00Z",
                returned_rows=1,
                source_rows=1,
                truncated=False,
                duration_ms=1,
            )
        )

        result = await registry.dispatch(
            "record_finding",
            {
                "title": "Suspicious connections from USER-001 on HOST-001",
                "description": "USER-001 connected outside business hours on HOST-001.",
                "severity": "high",
                "confidence": "medium",
                "entities": [{"type": "host", "value": "HOST-001"}],
                "evidence_query_ids": ["q_1"],
            },
        )
        assert result["recorded"]

        finding = dossier.findings[0]
        assert "svc-backup" in finding.title
        assert "PARIS-DC-01" in finding.description
        assert finding.entities[0].value == "PARIS-DC-01"
        assert "HOST-001" not in finding.title

    async def test_conclusion_timeline_is_rehydrated(self):
        vault = TokenVault()
        vault.token_for("host", "PARIS-DC-01")
        registry, dossier, _ = self._registry_and_dossier(vault)

        await registry.dispatch(
            "conclude_hunt",
            {
                "verdict": "suspicious",
                "summary": "Abnormal activity on HOST-001.",
                "limitations": "HOST-001 not covered by Defender.",
                "timeline": [
                    {
                        "timestamp": "2026-01-01T00:00:00Z",
                        "event": "First connection on HOST-001",
                        "source": "sentinel",
                    }
                ],
            },
        )

        conclusion = dossier.conclusion
        assert "PARIS-DC-01" in conclusion.summary
        assert "PARIS-DC-01" in conclusion.limitations
        assert "PARIS-DC-01" in conclusion.timeline[0].event


class TestBriefingBoundary:
    def test_hypothesis_is_tokenized_before_entering_the_prompt(self):
        from orchestrator.events import EventStream
        from orchestrator.loop import HuntOrchestrator

        vault = TokenVault(internal_suffixes=("corp.example",))
        dossier = Dossier(
            hunt_id="hunt_test",
            hypothesis=(
                "Check the connections of srv-payroll.corp.example and 10.20.30.40 "
                "on the Volt Typhoon campaign."
            ),
            analyst="a",
        )
        orchestrator = HuntOrchestrator(
            dossier=dossier,
            registry=None,
            journal=None,
            budget=HuntBudget(limits=Budgets()),
            stream=EventStream("hunt_test"),
            gateway=None,
            model="query-model",
            available_sources=["sentinel"],
            vault=vault,
        )

        briefing = orchestrator._briefing()

        assert "srv-payroll.corp.example" not in briefing
        assert "10.20.30.40" not in briefing
        assert "HOST-001" in briefing
        assert "IP-INT-001" in briefing
        assert "Volt Typhoon" in briefing
        assert "srv-payroll.corp.example" in dossier.hypothesis


class TestBulkFieldConsistency:
    """A value seen in a named field is masked everywhere, even in a bulk field placed
    before it. This is the guarantee for the SIEMs' "additional" fields."""

    def _settings(self):
        return Settings(_env_file=None, internal_hostname_suffixes="corp.internal")

    def test_account_in_bulk_field_before_named_field_does_not_leak(self):
        settings = self._settings()
        vault = TokenVault(internal_suffixes=("corp.internal",))
        row = {
            "AdditionalFields": "account svc-backup seen on PAR-DC-01.corp.internal",
            "Account": "svc-backup",
        }
        out = mask_row(row, settings.masking, tokenization=settings.tokenization, vault=vault)

        assert "svc-backup" not in out["AdditionalFields"]
        assert "USER-001" in out["AdditionalFields"]
        assert "HOST-001" in out["AdditionalFields"]

    def test_name_and_email_are_masked_in_bulk_field(self):
        settings = self._settings()
        vault = TokenVault(internal_suffixes=("corp.internal",))
        row = {
            "GivenName": "Mark",
            "Surname": "Anderson",
            "AccountUpn": "m.anderson@internal.example",
            "AdditionalFields": (
                "Mark Anderson (m.anderson@internal.example) on PAR-FS-03.corp.internal"
            ),
        }
        out = mask_row(row, settings.masking, tokenization=settings.tokenization, vault=vault)

        bulk = out["AdditionalFields"]
        assert "Mark" not in bulk
        assert "Anderson" not in bulk
        assert "m.anderson@internal.example" not in bulk
        assert "PAR-FS-03" not in bulk

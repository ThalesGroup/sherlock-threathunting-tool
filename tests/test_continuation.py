"""In-place continuation of an interrupted hunt: saved state, resumed loop."""

from middleware.budgets import Budgets, HuntBudget
from middleware.executor import QueryRecord, record_from_payload, record_to_payload
from middleware.tokenization import TokenVault


class TestVaultSnapshot:
    def test_roundtrip_preserves_both_directions(self):
        vault = TokenVault(internal_suffixes=("corp.local",))
        token = vault.token_for("host", "PAR-FS-03")
        vault.token_for("user", "j.smith")
        vault.alias("john.smith", vault.token_for("data", "John Smith"))

        restored = TokenVault(internal_suffixes=("corp.local",))
        restored.load(vault.snapshot())

        assert restored.token_for("host", "PAR-FS-03") == token
        assert restored.detokenize_text("HOST-001 and USER-001") == "PAR-FS-03 and j.smith"
        assert "DATA-001" in restored.tokenize_text("file of john.smith")
        assert restored.token_for("host", "new-host") == "HOST-002"


class TestBudgetRestore:
    def test_counters_and_elapsed_are_carried_over(self):
        budget = HuntBudget(limits=Budgets(max_iterations=30))
        budget.restore(iterations=7, siem_queries=4, tokens=1200, elapsed_seconds=120.0)
        assert budget.iterations == 7
        assert budget.siem_queries == 4
        assert budget.tokens == 1200
        assert budget.elapsed_seconds >= 120.0


class TestRecordPayload:
    def test_roundtrip(self):
        record = QueryRecord(
            query_id="q_1",
            siem="sentinel",
            query="SigninLogs",
            executed_at="2026-07-01T10:00:00Z",
            returned_rows=2,
            source_rows=5,
            truncated=True,
            duration_ms=12,
            intent="Spot connections",
            columns=("Account",),
            sample=({"Account": "svc"},),
            model_sample=({"Account": "USER-001"},),
            anonymization={"semantic": "disabled"},
        )
        assert record_from_payload(record_to_payload(record)) == record
